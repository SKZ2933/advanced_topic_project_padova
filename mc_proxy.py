"""
Minecraft 1.8.9 Proxy - Position Interception
A TCP proxy that sits between client and server to intercept player position packets.

Supports online-mode servers:
- Microsoft/Mojang authentication
- AES-128-CFB8 encryption

Configuration:
- LOCAL_PORT  : Port the proxy listens on (client connects here)
- SERVER_HOST : Real Minecraft server address
- SERVER_PORT : Real Minecraft server port
- ONLINE_MODE : True for premium servers, False for cracked
"""

import socket
import threading
import zlib
import struct
import json
import os
import signal
import sys
import requests

from mc_protocol import (
    read_varint, write_varint, parse_server_packet, parse_client_packet,
    PACKET_IDS, read_string
)
from auth_microsoft import MinecraftAuth
from mc_crypto import (
    generate_shared_secret, encrypt_with_public_key,
    compute_server_hash, EncryptedSocketWrapper
)


# =============================================================================
# CONFIGURATION
# =============================================================================

LOCAL_HOST = "0.0.0.0"
LOCAL_PORT = 25566
SERVER_HOST = "mc.dikingvps.com"
SERVER_PORT = 25565
ONLINE_MODE = True  # True = premium server (authentication required)

# Shared data file for aimbot communication
SHARED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aimbot_data.json")


# =============================================================================
# SHARED DATA (Thread-safe player positions)
# =============================================================================

shared_data = {
    'my_position': {'x': 0, 'y': 0, 'z': 0, 'yaw': 0, 'pitch': 0},
    'players': {},  # entity_id -> {x, y, z, uuid}
    'lock': threading.Lock()
}


def export_to_file():
    """Export position data to JSON file for aimbot."""
    try:
        with shared_data['lock']:
            data = {
                'my_position': shared_data['my_position'].copy(),
                'players': {str(k): v for k, v in shared_data['players'].items()}
            }
        with open(SHARED_FILE, 'w') as f:
            json.dump(data, f)
    except:
        pass


# =============================================================================
# ENTITY TRACKER
# =============================================================================

class EntityTracker:
    """Tracks positions of PLAYERS only (ignores mobs and objects)."""

    def __init__(self):
        self.players = {}  # entity_id -> {x, y, z, uuid}
        self.my_entity_id = None

    def add_player(self, entity_id, x, y, z, uuid):
        """Add a new player (only called on Spawn Player packet 0x0C)."""
        self.players[entity_id] = {'x': x, 'y': y, 'z': z, 'uuid': uuid}
        return self.players[entity_id]

    def update_position_delta(self, entity_id, dx, dy, dz):
        """Update position by delta - only if it's a known player."""
        if entity_id in self.players:
            self.players[entity_id]['x'] += dx
            self.players[entity_id]['y'] += dy
            self.players[entity_id]['z'] += dz
            return self.players[entity_id]
        return None

    def set_position(self, entity_id, x, y, z):
        """Set absolute position - only if it's a known player."""
        if entity_id in self.players:
            self.players[entity_id]['x'] = x
            self.players[entity_id]['y'] = y
            self.players[entity_id]['z'] = z
            return self.players[entity_id]
        return None

    def remove_player(self, entity_id):
        if entity_id in self.players:
            del self.players[entity_id]

    def is_player(self, entity_id):
        return entity_id in self.players

    def get_all_players(self):
        return self.players


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def write_string(s):
    """Write a Minecraft string (VarInt length + UTF-8)."""
    encoded = s.encode('utf-8')
    return write_varint(len(encoded)) + encoded


def rewrite_handshake(packet_data, target_host, target_port):
    """
    Rewrite the Handshake packet to change server address.
    Preserves any trailing data (like Status Request that might follow).
    """
    offset = 0
    packet_length, offset = read_varint(packet_data, offset)
    if packet_length is None:
        return packet_data

    handshake_end = offset + packet_length
    trailing_data = packet_data[handshake_end:]
    payload = packet_data[offset:handshake_end]

    # Parse original handshake
    off = 0
    packet_id, off = read_varint(payload, off)
    if packet_id != 0x00:
        return packet_data

    protocol_version, off = read_varint(payload, off)
    _, off = read_string(payload, off)  # Original server address (ignored)
    if off + 2 > len(payload):
        return packet_data
    off += 2  # Original port (ignored)
    next_state, off = read_varint(payload, off)

    # Build new handshake with target address
    new_payload = write_varint(0x00)  # Packet ID
    new_payload += write_varint(protocol_version)
    new_payload += write_string(target_host)
    new_payload += struct.pack('>H', target_port)
    new_payload += write_varint(next_state)

    return write_varint(len(new_payload)) + new_payload + trailing_data


# =============================================================================
# MINECRAFT PROXY
# =============================================================================

class MinecraftProxy:
    """Main proxy class that handles client connections and packet forwarding."""

    def __init__(self, local_host, local_port, server_host, server_port):
        self.local_host = local_host
        self.local_port = local_port
        self.server_host = server_host
        self.server_port = server_port
        self.tracker = EntityTracker()

    # =========================================================================
    # PACKET HANDLING
    # =========================================================================

    def handle_packet(self, data, direction, compression_threshold):
        """Parse a packet and extract position information."""
        offset = 0
        packet_length, offset = read_varint(data, offset)
        if packet_length is None:
            return

        packet_data = data[offset:offset + packet_length]
        offset = 0

        # Handle compression
        if compression_threshold >= 0:
            data_length, offset = read_varint(packet_data, offset)
            if data_length and data_length > 0:
                try:
                    packet_data = zlib.decompress(packet_data[offset:])
                    offset = 0
                except:
                    return

        # Read packet ID
        packet_id, offset = read_varint(packet_data, offset)
        if packet_id is None:
            return

        # Parse position packets (server -> client only)
        if direction == "S->C" and packet_id in PACKET_IDS:
            try:
                result = parse_server_packet(packet_id, packet_data[offset:])
                if result:
                    self.process_position(result)
            except:
                pass

    def process_position(self, result):
        """Process parsed position data and update tracker/shared data."""
        
        # New player spawned
        if result['type'] == 'spawn_player':
            self.tracker.add_player(
                result['entity_id'],
                result['x'], result['y'], result['z'],
                result.get('uuid', 'unknown')
            )
            uuid_short = result.get('uuid', '?')[:8]
            print(f"\n>>> PLAYER DETECTED: ID={result['entity_id']} UUID={uuid_short}...")
            print(f"    Position: X={result['x']:.1f} Y={result['y']:.1f} Z={result['z']:.1f}")

            with shared_data['lock']:
                shared_data['players'][result['entity_id']] = {
                    'x': result['x'], 'y': result['y'], 'z': result['z'],
                    'uuid': result.get('uuid', 'unknown')
                }

        # Player teleported (absolute position)
        elif result['type'] == 'teleport':
            entity = self.tracker.set_position(
                result['entity_id'],
                result['x'], result['y'], result['z']
            )
            if entity:
                print(f"\r[PLAYER {result['entity_id']:3d}] X={result['x']:8.1f} Y={result['y']:5.1f} Z={result['z']:8.1f}  ", end="", flush=True)
                with shared_data['lock']:
                    if result['entity_id'] in shared_data['players']:
                        shared_data['players'][result['entity_id']].update({
                            'x': result['x'], 'y': result['y'], 'z': result['z']
                        })

        # Player moved (delta position)
        elif result['type'] in ['position_delta', 'position_rotation_delta']:
            entity = self.tracker.update_position_delta(
                result['entity_id'],
                result['dx'], result['dy'], result['dz']
            )
            if entity:
                print(f"\r[PLAYER {result['entity_id']:3d}] X={entity['x']:8.1f} Y={entity['y']:5.1f} Z={entity['z']:8.1f}  ", end="", flush=True)
                with shared_data['lock']:
                    if result['entity_id'] in shared_data['players']:
                        shared_data['players'][result['entity_id']].update({
                            'x': entity['x'], 'y': entity['y'], 'z': entity['z']
                        })

        # Our own position (from server)
        elif result['type'] == 'my_position':
            with shared_data['lock']:
                shared_data['my_position'].update({
                    'x': result['x'], 'y': result['y'], 'z': result['z'],
                    'yaw': result.get('yaw', 0), 'pitch': result.get('pitch', 0)
                })

        export_to_file()

    # =========================================================================
    # FORWARDING THREADS
    # =========================================================================

    def forward_client_to_server(self, client_socket, server_socket, state):
        """Forward data from client to server, parsing client packets."""
        first_packet = True
        compression = state.get('compression_threshold', -1)

        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break

                # Rewrite first packet (Handshake) in handshaking phase
                if first_packet and state['phase'] == 'handshaking':
                    data = rewrite_handshake(data, self.server_host, self.server_port)
                    first_packet = False

                    # Detect next_state
                    offset = 0
                    plen, offset = read_varint(data, offset)
                    if plen:
                        payload = data[offset:offset + plen]
                        p = 0
                        _, p = read_varint(payload, p)  # Packet ID
                        _, p = read_varint(payload, p)  # Protocol version
                        _, p = read_string(payload, p)  # Server address
                        p += 2  # Port
                        next_state, _ = read_varint(payload, p)
                        state['phase'] = 'status' if next_state == 1 else 'login'

                # Extract username from Login Start
                if state['phase'] == 'login' and 'username' not in state:
                    try:
                        offset = 0
                        plen, offset = read_varint(data, offset)
                        if plen and 0 < plen < 50:
                            pid, poff = read_varint(data, offset)
                            if pid == 0x00:
                                name, _ = read_string(data, poff)
                                if name and 3 <= len(name) <= 16:
                                    if all(c.isalnum() or c == '_' for c in name):
                                        state['username'] = name
                                        print(f"[LOGIN] Player: {name}")
                    except:
                        pass

                # Parse client position packets in play phase
                if state['phase'] == 'play':
                    try:
                        compression = state.get('compression_threshold', -1)
                        offset = 0
                        plen, offset = read_varint(data, offset)
                        if plen and plen > 0:
                            pdata = data[offset:offset + plen]
                            p = 0

                            if compression >= 0:
                                dlen, p = read_varint(pdata, p)
                                if dlen and dlen > 0:
                                    try:
                                        pdata = zlib.decompress(pdata[p:])
                                        p = 0
                                    except:
                                        pass

                            pid, p = read_varint(pdata, p)
                            # Player Position (0x04), Look (0x05), Position+Look (0x06)
                            if pid in [0x04, 0x05, 0x06]:
                                result = parse_client_packet(pid, pdata[p:])
                                if result:
                                    with shared_data['lock']:
                                        if 'x' in result:
                                            shared_data['my_position']['x'] = result['x']
                                            shared_data['my_position']['y'] = result['y']
                                            shared_data['my_position']['z'] = result['z']
                                        if 'yaw' in result:
                                            shared_data['my_position']['yaw'] = result['yaw']
                                            shared_data['my_position']['pitch'] = result['pitch']
                                    export_to_file()
                    except:
                        pass

                server_socket.sendall(data)

            except Exception as e:
                print(f"\n[!] Error C->S: {e}")
                break

        try:
            client_socket.close()
            server_socket.close()
        except:
            pass

    def forward_server_to_client(self, server_socket, client_socket, state):
        """Forward data from server to client, parsing server packets."""
        buffer = b""
        compression = state.get('compression_threshold', -1)

        while True:
            try:
                data = server_socket.recv(4096)
                if not data:
                    break

                buffer += data

                # Parse complete packets from buffer
                while len(buffer) > 0:
                    try:
                        length, length_size = read_varint(buffer, 0)
                        if length is None or len(buffer) < length_size + length:
                            break

                        packet = buffer[:length_size + length]
                        buffer = buffer[length_size + length:]

                        # Handle login phase packets
                        if state['phase'] == 'login':
                            offset = length_size

                            if compression >= 0:
                                data_length, offset = read_varint(packet, offset)
                                if data_length and data_length > 0:
                                    try:
                                        decompressed = zlib.decompress(packet[offset:])
                                        pid, _ = read_varint(decompressed, 0)
                                    except:
                                        pid = None
                                else:
                                    pid, _ = read_varint(packet, offset)
                            else:
                                pid, offset = read_varint(packet, offset)

                            if pid is not None:
                                if pid == 0x01:  # Encryption Request
                                    print("[!] ENCRYPTION REQUEST - Server is NOT offline mode!")
                                elif pid == 0x03:  # Set Compression
                                    threshold, _ = read_varint(packet, offset)
                                    compression = threshold if threshold else -1
                                    state['compression_threshold'] = compression
                                    print(f"[INFO] Compression enabled (threshold={compression})")
                                elif pid == 0x02:  # Login Success
                                    state['phase'] = 'play'
                                    username = state.get('username', 'unknown')
                                    print(f"[OK] Connected as {username} - Tracking active")

                        # Parse play phase packets
                        if state['phase'] == 'play':
                            try:
                                self.handle_packet(packet, "S->C", compression)
                            except:
                                pass

                    except:
                        break

                client_socket.sendall(data)

            except Exception as e:
                print(f"\n[!] Error S->C: {e}")
                break

        try:
            server_socket.close()
            client_socket.close()
        except:
            pass

    # =========================================================================
    # ENCRYPTION HANDSHAKE
    # =========================================================================

    def handle_encryption_handshake(self, server_socket, auth_data):
        """
        Handle encryption handshake with server.
        
        1. Receive Encryption Request
        2. Generate shared secret, encrypt with RSA
        3. Validate session with Mojang
        4. Send Encryption Response
        5. Enable AES encryption
        
        Returns:
            (EncryptedSocketWrapper, compression_threshold) or None
        """
        buffer = b""

        while True:
            data = server_socket.recv(4096)
            if not data:
                return None
            buffer += data

            # Read packet
            offset = 0
            packet_length, offset = read_varint(buffer, offset)
            if packet_length is None or len(buffer) < offset + packet_length:
                continue

            packet_data = buffer[offset:offset + packet_length]
            buffer = buffer[offset + packet_length:]

            p = 0
            packet_id, p = read_varint(packet_data, p)

            # Encryption Request (0x01)
            if packet_id == 0x01:
                print("[CRYPTO] Encryption Request received")

                # Parse packet
                server_id, p = read_string(packet_data, p)
                pubkey_len, p = read_varint(packet_data, p)
                if pubkey_len is None:
                    return None
                public_key = packet_data[p:p + pubkey_len]
                p += pubkey_len
                verify_len, p = read_varint(packet_data, p)
                if verify_len is None:
                    return None
                verify_token = packet_data[p:p + verify_len]

                print(f"[CRYPTO] Server ID: '{server_id}'")
                print(f"[CRYPTO] Public Key: {len(public_key)} bytes")

                # Generate shared secret
                shared_secret = generate_shared_secret()
                print(f"[CRYPTO] Shared Secret: {shared_secret.hex()[:16]}...")

                # Compute server hash for Mojang validation
                server_hash = compute_server_hash(server_id, shared_secret, public_key)
                print(f"[CRYPTO] Server Hash: {server_hash}")

                # Validate session with Mojang
                print("[CRYPTO] Validating session with Mojang...")
                try:
                    response = requests.post(
                        "https://sessionserver.mojang.com/session/minecraft/join",
                        json={
                            "accessToken": auth_data['access_token'],
                            "selectedProfile": auth_data['uuid'],
                            "serverId": server_hash
                        },
                        headers={"Content-Type": "application/json"}
                    )
                    if response.status_code == 204:
                        print("[CRYPTO] Mojang session validated!")
                    else:
                        print(f"[!] Mojang session error: {response.status_code} {response.text}")
                        return None
                except Exception as e:
                    print(f"[!] Mojang session error: {e}")
                    return None

                # Encrypt shared secret and verify token with RSA
                encrypted_secret = encrypt_with_public_key(public_key, shared_secret)
                encrypted_verify = encrypt_with_public_key(public_key, verify_token)

                # Build Encryption Response (0x01)
                response_payload = write_varint(0x01)
                response_payload += write_varint(len(encrypted_secret)) + encrypted_secret
                response_payload += write_varint(len(encrypted_verify)) + encrypted_verify

                server_socket.sendall(write_varint(len(response_payload)) + response_payload)
                print("[CRYPTO] Encryption Response sent")

                # Enable AES encryption
                encrypted_socket = EncryptedSocketWrapper(server_socket, shared_secret)
                print("[CRYPTO] AES encryption enabled!")

                # Receive Set Compression and Login Success (now encrypted)
                login_complete = False
                compression = -1

                print("[DEBUG] Waiting for post-encryption packets...")
                while not login_complete:
                    try:
                        if not buffer:
                            enc_data = encrypted_socket.recv(4096)
                            if not enc_data:
                                print("[!] Connection lost during login")
                                return None
                            buffer += enc_data
                    except Exception as e:
                        print(f"[!] Recv error after encryption: {e}")
                        return None

                    while len(buffer) > 0:
                        off = 0
                        plen, off = read_varint(buffer, off)
                        if plen is None or len(buffer) < off + plen:
                            try:
                                more = encrypted_socket.recv(4096)
                                if not more:
                                    return None
                                buffer += more
                                continue
                            except:
                                return None

                        pkt = buffer[:off + plen]
                        buffer = buffer[off + plen:]
                        p_off = off

                        # Handle compression
                        if compression >= 0:
                            dlen, p_off = read_varint(pkt, p_off)
                            if dlen is not None and dlen > 0:
                                try:
                                    pkt_content = zlib.decompress(pkt[p_off:])
                                    p_off = 0
                                except Exception as e:
                                    print(f"[!] Decompression error: {e}")
                                    return None
                            else:
                                pkt_content = pkt
                        else:
                            pkt_content = pkt

                        pid, np = read_varint(pkt_content, p_off)
                        p_off = np

                        if pid == 0x03:  # Set Compression
                            thresh, _ = read_varint(pkt_content, p_off)
                            compression = thresh if thresh else -1
                            print(f"[CRYPTO] Set Compression (threshold={compression})")
                        elif pid == 0x02:  # Login Success
                            print("[CRYPTO] Login Success!")
                            login_complete = True
                        elif pid == 0x00:  # Disconnect
                            try:
                                reason, _ = read_string(pkt_content, p_off)
                                print(f"[!] Disconnected during login: {reason}")
                            except:
                                print("[!] Disconnected during login")
                            return None

                return encrypted_socket, compression

            # Login Success without encryption (offline mode)
            elif packet_id == 0x02:
                print("[INFO] Server is offline mode (no encryption)")
                return None

            # Set Compression without encryption
            elif packet_id == 0x03:
                threshold, _ = read_varint(packet_data, p)
                print(f"[INFO] Set Compression (no encryption): {threshold}")
                return None

    # =========================================================================
    # CLIENT HANDLER
    # =========================================================================

    def handle_client(self, client_socket, address):
        """Handle a client connection."""
        print(f"\n[+] New connection from {address}")

        # Authenticate if online mode
        auth_data = None
        if ONLINE_MODE:
            print("[*] Online Mode - Authentication required")
            try:
                auth = MinecraftAuth()
                auth_data = auth.authenticate()
                print(f"[OK] Authenticated: {auth_data['username']}")
            except Exception as e:
                print(f"[!] Authentication failed: {e}")
                client_socket.close()
                return

        # Connect to real server
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((self.server_host, self.server_port))
            server_socket.settimeout(None)
            print(f"[+] Connected to server {self.server_host}:{self.server_port}")
        except Exception as e:
            print(f"[!] Cannot connect to server: {e}")
            client_socket.close()
            return

        state = {'phase': 'handshaking', 'encrypted': False}

        # Handle online mode authentication
        if ONLINE_MODE and auth_data:
            client_data = client_socket.recv(4096)
            if client_data:
                # Parse handshake to get next_state
                off = 0
                plen = 0
                next_state = 2  # Default: assume login
                try:
                    plen, off = read_varint(client_data, off)
                    if plen is None:
                        plen = 0
                    else:
                        payload = client_data[off:off + plen]
                        p = 0
                        _, p = read_varint(payload, p)  # Packet ID
                        _, p = read_varint(payload, p)  # Protocol
                        _, p = read_string(payload, p)  # Address
                        p += 2  # Port
                        next_state_val, _ = read_varint(payload, p)
                        if next_state_val is not None:
                            next_state = next_state_val
                except:
                    pass

                if next_state == 1:
                    # Status ping - transparent passthrough
                    rewritten = rewrite_handshake(client_data, self.server_host, self.server_port)
                    server_socket.sendall(rewritten)
                    state['phase'] = 'status'
                else:
                    # Login - full authentication
                    handshake_len = off + (plen or 0)
                    trailing = client_data[handshake_len:]
                    handshake_pkt = client_data[:handshake_len]

                    rewritten = rewrite_handshake(handshake_pkt, self.server_host, self.server_port)
                    server_socket.sendall(rewritten)
                    state['phase'] = 'login'

                    # Get Login Start
                    login_data = trailing if trailing else client_socket.recv(4096)
                    if login_data:
                        try:
                            lo = 0
                            lp, lo = read_varint(login_data, lo)
                            pid, po = read_varint(login_data, lo)
                            if pid == 0x00:
                                name, _ = read_string(login_data, po)
                                print(f"[LOGIN] Client connecting as: {name}")
                        except:
                            pass

                        # Send Login Start with authenticated username
                        real_username = str(auth_data['username'])
                        login_payload = write_varint(0x00)
                        login_payload += write_varint(len(real_username.encode('utf-8')))
                        login_payload += real_username.encode('utf-8')
                        server_socket.sendall(write_varint(len(login_payload)) + login_payload)
                        print(f"[LOGIN] Sent Login Start: {real_username}")

                    # Handle encryption
                    result = self.handle_encryption_handshake(server_socket, auth_data)

                    if result:
                        encrypted_socket, compression = result
                        state['encrypted'] = True
                        state['phase'] = 'play'
                        state['compression_threshold'] = compression
                        server_socket = encrypted_socket

                        # Send Set Compression to client
                        if compression >= 0:
                            comp_payload = write_varint(0x03) + write_varint(compression)
                            client_socket.sendall(write_varint(len(comp_payload)) + comp_payload)
                            print(f"[PROXY] Sent Set Compression to client (threshold={compression})")

                        # Send Login Success to client
                        uuid_str = str(auth_data['uuid'])
                        uuid_formatted = f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:]}"
                        username = str(auth_data['username'])

                        login_success = write_varint(0x02)
                        login_success += write_varint(len(uuid_formatted)) + uuid_formatted.encode('utf-8')
                        login_success += write_varint(len(username)) + username.encode('utf-8')

                        if compression >= 0:
                            inner = write_varint(0) + login_success
                            login_pkt = write_varint(len(inner)) + inner
                        else:
                            login_pkt = write_varint(len(login_success)) + login_success

                        client_socket.sendall(login_pkt)
                        print(f"[PROXY] Sent Login Success to client ({username})")
                        print("[OK] Encrypted handshake complete - Play mode active")
                    else:
                        print("[INFO] Continuing without encryption")

        # Store sockets in state
        state['server_socket'] = server_socket
        state['client_socket'] = client_socket

        # Start forwarding threads
        t1 = threading.Thread(target=self.forward_client_to_server, args=(client_socket, server_socket, state))
        t2 = threading.Thread(target=self.forward_server_to_client, args=(server_socket, client_socket, state))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        print(f"\n[-] Connection closed for {address}")

        # Summary
        players = self.tracker.get_all_players()
        if players:
            print("\n[SUMMARY] Players detected:")
            for eid, data in players.items():
                print(f"  ID={eid}: X={data['x']:.1f} Y={data['y']:.1f} Z={data['z']:.1f}")

    # =========================================================================
    # MAIN LOOP
    # =========================================================================

    def start(self):
        """Start the proxy server."""
        print("=" * 60)
        print("MINECRAFT 1.8.9 PROXY - POSITION INTERCEPTION")
        print("=" * 60)
        print(f"\n[*] Configuration:")
        print(f"    Listen on : {self.local_host}:{self.local_port}")
        print(f"    Server    : {self.server_host}:{self.server_port}")
        print(f"\n[*] In Minecraft, connect to: localhost:{self.local_port}")
        print("=" * 60)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.local_host, self.local_port))
        self.server_socket.listen(5)
        self.running = True

        def signal_handler(sig, frame):
            print("\n[*] Ctrl+C received, shutting down...")
            self.running = False
            try:
                self.server_socket.close()
            except:
                pass
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        print(f"\n[+] Proxy listening on port {self.local_port}...")
        print("[*] Waiting for Minecraft connection... (Ctrl+C to stop)\n")

        try:
            while self.running:
                self.server_socket.settimeout(1.0)
                try:
                    client_socket, address = self.server_socket.accept()
                    handler = threading.Thread(target=self.handle_client, args=(client_socket, address))
                    handler.daemon = True
                    handler.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            print("\n[*] Proxy stopped.")
            try:
                self.server_socket.close()
            except:
                pass


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    proxy = MinecraftProxy(LOCAL_HOST, LOCAL_PORT, SERVER_HOST, SERVER_PORT)
    proxy.start()


if __name__ == "__main__":
    main()
