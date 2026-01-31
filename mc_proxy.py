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
import signal
import sys
import requests

from multiprocessing import shared_memory

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
ONLINE_MODE = False  # True = premium server (authentication required)


# =============================================================================
# PACKET UTILITIES
# =============================================================================

def write_string(text: str) -> bytes:
    """Write a Minecraft string (VarInt length + UTF-8)."""
    encoded = text.encode('utf-8')
    return write_varint(len(encoded)) + encoded


def build_packet(packet_id: int, payload: bytes = b"") -> bytes:
    """Build a complete Minecraft packet with length prefix."""
    packet_data = write_varint(packet_id) + payload
    return write_varint(len(packet_data)) + packet_data


def build_compressed_packet(packet_id: int, payload: bytes, compression_threshold: int) -> bytes:
    """Build a packet with compression header (uncompressed, data_length=0)."""
    inner_data = write_varint(packet_id) + payload
    # data_length=0 means uncompressed
    packet_with_header = write_varint(0) + inner_data
    return write_varint(len(packet_with_header)) + packet_with_header


class PacketReader:
    """Handles buffered packet reading with optional decompression."""

    def __init__(self, compression_threshold: int = -1):
        self.buffer = b""
        self.compression_threshold = compression_threshold

    def add_data(self, data: bytes):
        """Add received data to the buffer."""
        self.buffer += data

    def read_packet(self):
        """
        Try to read a complete packet from the buffer.
        
        Returns:
            tuple: (packet_id, payload_bytes, raw_packet) or (None, None, None) if incomplete
        """
        if not self.buffer:
            return None, None, None

        offset = 0
        packet_length, offset = read_varint(self.buffer, offset)
        
        if packet_length is None or len(self.buffer) < offset + packet_length:
            return None, None, None

        raw_packet = self.buffer[:offset + packet_length]
        packet_data = self.buffer[offset:offset + packet_length]
        self.buffer = self.buffer[offset + packet_length:]

        payload_offset = 0

        # Handle compression if enabled
        if self.compression_threshold >= 0:
            data_length, payload_offset = read_varint(packet_data, payload_offset)
            if data_length and data_length > 0:
                try:
                    packet_data = zlib.decompress(packet_data[payload_offset:])
                    payload_offset = 0
                except zlib.error:
                    return None, None, None

        packet_id, payload_offset = read_varint(packet_data, payload_offset)
        if packet_id is None:
            return None, None, None

        payload = packet_data[payload_offset:]
        return packet_id, payload, raw_packet

    def has_data(self) -> bool:
        return len(self.buffer) > 0


# =============================================================================
# SHARED MEMORY CONFIGURATION
# =============================================================================
# 
# Memory Layout (fixed size for direct access):
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ Offset 0-3   : player_count (int32) - number of tracked players        │
# │ Offset 4-43  : my_position (5 × float64) - x, y, z, yaw, pitch          │
# │ Offset 44+   : players array (MAX_PLAYERS × 32 bytes each)              │
# │               Each player: entity_id (int32) + x, y, z (3 × float64)    │
# └─────────────────────────────────────────────────────────────────────────┘
#
# This replaces JSON file I/O with direct RAM access between processes.

SHARED_MEMORY_NAME = "mc_proxy_positions"
MAX_PLAYERS = 50

# Struct formats (using Python's struct module)
# Use '<' prefix for little-endian, no padding (consistent across platforms)
# 'i' = int32 (4 bytes), 'd' = float64/double (8 bytes)
HEADER_FORMAT = '<i5d'          # player_count + my_pos(x,y,z,yaw,pitch) = 44 bytes
PLAYER_WRITE_FORMAT = '<i3d'    # entity_id + x,y,z = 28 bytes (what we write)
HEADER_SIZE = 44                # Fixed: 4 + 5*8 = 44 bytes
PLAYER_SIZE = 32                # 32 bytes per player slot (28 data + 4 padding)
TOTAL_SHM_SIZE = HEADER_SIZE + (PLAYER_SIZE * MAX_PLAYERS)  # ~1.6 KB


# =============================================================================
# PLAYER POSITION STORAGE
# =============================================================================

class PlayerPositionStore:
    """
    Thread-safe storage for player positions with shared memory export.
    
    Instead of writing JSON to disk on every update (slow I/O),
    we write directly to a shared memory block that the aimbot can read.
    """

    def __init__(self):
        # Position data
        self.my_position: dict[str, float] = {'x': 0.0, 'y': 0.0, 'z': 0.0, 'yaw': 0.0, 'pitch': 0.0}
        self.other_players: dict[int, dict] = {}  # entity_id -> {x, y, z, uuid}
        self._lock = threading.Lock()
        
        # Initialize shared memory
        self._shm: shared_memory.SharedMemory = self._create_shared_memory()

    def _create_shared_memory(self) -> shared_memory.SharedMemory:
        """
        Create or attach to shared memory block.
        
        We try to create new shared memory. If it already exists (from a previous
        run that didn't clean up), we unlink it first and create fresh.
        """
        
        try:
            # Try to create new shared memory
            shm = shared_memory.SharedMemory(
                name=SHARED_MEMORY_NAME,
                create=True,
                size=TOTAL_SHM_SIZE
            )
            print(f"[SHM] Created shared memory: {SHARED_MEMORY_NAME} ({TOTAL_SHM_SIZE} bytes)")
            
            # Zero-initialize the memory (buf is always valid after successful creation)
            shm.buf[:TOTAL_SHM_SIZE] = b'\x00' * TOTAL_SHM_SIZE  # type: ignore[index]
            return shm
            
        except FileExistsError:
            # Shared memory exists from previous run - reuse it
            shm = shared_memory.SharedMemory(name=SHARED_MEMORY_NAME, create=False)
            print(f"[SHM] Attached to existing shared memory: {SHARED_MEMORY_NAME}")
            
            # Zero-initialize to clear stale data (buf is always valid after successful attach)
            shm.buf[:TOTAL_SHM_SIZE] = b'\x00' * TOTAL_SHM_SIZE  # type: ignore[index]
            return shm

    def cleanup(self):
        """
        Clean up shared memory when proxy shuts down.
        
        Must be called on exit to avoid memory leaks.
        """
        if self._shm:
            try:
                self._shm.close()
                self._shm.unlink()  # Remove the shared memory block
                print("[SHM] Shared memory cleaned up")
            except Exception as e:
                print(f"[SHM] Cleanup warning: {e}")

    def update_my_position(self, x: float | None = None, y: float | None = None, 
                           z: float | None = None, yaw: float | None = None, 
                           pitch: float | None = None):
        """Update local player's position and/or rotation."""
        with self._lock:
            if x is not None:
                self.my_position['x'] = x
            if y is not None:
                self.my_position['y'] = y
            if z is not None:
                self.my_position['z'] = z
            if yaw is not None:
                self.my_position['yaw'] = yaw
            if pitch is not None:
                self.my_position['pitch'] = pitch
        self._export()

    def add_player(self, entity_id: int, x: float, y: float, z: float, uuid: str):
        """Add a new player to tracking."""
        with self._lock:
            self.other_players[entity_id] = {'x': x, 'y': y, 'z': z, 'uuid': uuid}
        self._export()

    def update_player_position(self, entity_id: int, x: float, y: float, z: float):
        """Update a tracked player's absolute position."""
        with self._lock:
            if entity_id in self.other_players:
                self.other_players[entity_id].update({'x': x, 'y': y, 'z': z})
        self._export()

    def update_player_position_delta(self, entity_id: int, dx: float, dy: float, dz: float):
        """Update a tracked player's position by delta."""
        with self._lock:
            if entity_id in self.other_players:
                player = self.other_players[entity_id]
                player['x'] += dx
                player['y'] += dy
                player['z'] += dz
        self._export()

    def remove_player(self, entity_id: int):
        """Remove a player from tracking."""
        with self._lock:
            self.other_players.pop(entity_id, None)
        self._export()

    def get_player(self, entity_id: int) -> dict:
        """Get a player's current data."""
        with self._lock:
            return self.other_players.get(entity_id, {}).copy()

    def get_all_players(self) -> dict:
        """Get all tracked players."""
        with self._lock:
            return {eid: data.copy() for eid, data in self.other_players.items()}

    def is_tracked_player(self, entity_id: int) -> bool:
        """Check if entity_id is a tracked player."""
        with self._lock:
            return entity_id in self.other_players

    def _export(self):
        """
        Export position data to shared memory for aimbot.
        
        Memory layout:
        - Bytes 0-3: player count (int32)
        - Bytes 4-43: my_position as 5 doubles (x, y, z, yaw, pitch)
        - Bytes 44+: each player as (entity_id: int32, x, y, z: doubles, 4 padding)
        
        This is ~100x faster than JSON file I/O because:
        1. No serialization overhead
        2. No disk I/O
        3. No file system locks
        """
        if not self._shm:
            return
            
        try:
            with self._lock:
                # Get player list (limit to MAX_PLAYERS)
                players = list(self.other_players.items())[:MAX_PLAYERS]
                player_count = len(players)
                
                # Pack header: player_count + my_position
                buf = self._shm.buf  # Local reference for type checker
                struct.pack_into(
                    HEADER_FORMAT,
                    buf,  # type: ignore[arg-type]
                    0,  # offset
                    player_count,
                    self.my_position['x'],
                    self.my_position['y'],
                    self.my_position['z'],
                    self.my_position['yaw'],
                    self.my_position['pitch']
                )
                
                # Pack each player into the array section
                for i, (entity_id, player_data) in enumerate(players):
                    offset = HEADER_SIZE + (i * PLAYER_SIZE)
                    struct.pack_into(
                        PLAYER_WRITE_FORMAT,
                        buf,  # type: ignore[arg-type]
                        offset,
                        entity_id,
                        player_data['x'],
                        player_data['y'],
                        player_data['z']
                    )
                    
        except Exception:
            # Silently ignore errors (same as original JSON export)
            pass


# =============================================================================
# ENTITY TRACKER
# =============================================================================

class EntityTracker:
    """Tracks which entity IDs are players and updates their positions."""

    def __init__(self, position_store: PlayerPositionStore):
        self.position_store = position_store
        self.my_entity_id = None

    def on_spawn_player(self, entity_id: int, x: float, y: float, z: float, uuid: str):
        """Handle Spawn Player packet (0x0C) - only real players trigger this."""
        self.position_store.add_player(entity_id, x, y, z, uuid)
        uuid_short = uuid[:8] if uuid else '?'
        print(f"\n>>> PLAYER DETECTED: ID={entity_id} UUID={uuid_short}...")
        print(f"    Position: X={x:.1f} Y={y:.1f} Z={z:.1f}")

    def on_entity_teleport(self, entity_id: int, x: float, y: float, z: float):
        """Handle Entity Teleport packet - only update if it's a tracked player."""
        if self.position_store.is_tracked_player(entity_id):
            self.position_store.update_player_position(entity_id, x, y, z)
            print(f"\r[PLAYER {entity_id:3d}] X={x:8.1f} Y={y:5.1f} Z={z:8.1f}  ", end="", flush=True)

    def on_entity_move(self, entity_id: int, dx: float, dy: float, dz: float):
        """Handle Entity Relative Move packet - only update if it's a tracked player."""
        if self.position_store.is_tracked_player(entity_id):
            self.position_store.update_player_position_delta(entity_id, dx, dy, dz)
            player = self.position_store.get_player(entity_id)
            if player:
                print(f"\r[PLAYER {entity_id:3d}] X={player['x']:8.1f} Y={player['y']:5.1f} Z={player['z']:8.1f}  ", 
                      end="", flush=True)

    def on_my_position(self, x: float, y: float, z: float, 
                       yaw: float | None = None, pitch: float | None = None):
        """Handle Player Position And Look packet (our own position from server)."""
        self.position_store.update_my_position(x=x, y=y, z=z, yaw=yaw, pitch=pitch)

    def on_destroy_entities(self, entity_ids: list):
        """Handle Destroy Entities packet."""
        for entity_id in entity_ids:
            self.position_store.remove_player(entity_id)


# =============================================================================
# HANDSHAKE REWRITER
# =============================================================================

def rewrite_handshake(packet_data: bytes, target_host: str, target_port: int) -> bytes:
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
    parse_offset = 0
    packet_id, parse_offset = read_varint(payload, parse_offset)
    if packet_id != 0x00:
        return packet_data

    protocol_version, parse_offset = read_varint(payload, parse_offset)
    _, parse_offset = read_string(payload, parse_offset)  # Original server address (ignored)
    if parse_offset + 2 > len(payload):
        return packet_data
    parse_offset += 2  # Original port (ignored)
    next_state, parse_offset = read_varint(payload, parse_offset)

    # Build new handshake with target address
    new_payload = write_varint(0x00)  # Packet ID
    new_payload += write_varint(protocol_version)
    new_payload += write_string(target_host)
    new_payload += struct.pack('>H', target_port)
    new_payload += write_varint(next_state)

    return write_varint(len(new_payload)) + new_payload + trailing_data


# =============================================================================
# MOJANG SESSION VALIDATOR
# =============================================================================

class MojangSessionValidator:
    """Handles session validation with Mojang servers."""

    MOJANG_SESSION_URL = "https://sessionserver.mojang.com/session/minecraft/join"

    @staticmethod
    def join_server(access_token: str, uuid: str, server_hash: str) -> bool:
        """
        Register session with Mojang (step 3 of encryption flow).
        Returns True on success, False on failure.
        """
        try:
            response = requests.post(
                MojangSessionValidator.MOJANG_SESSION_URL,
                json={
                    "accessToken": access_token,
                    "selectedProfile": uuid,
                    "serverId": server_hash
                },
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if response.status_code == 204:
                print("[CRYPTO] Mojang session validated!")
                return True
            else:
                print(f"[!] Mojang session error: {response.status_code} {response.text}")
                return False
        except requests.RequestException as e:
            print(f"[!] Mojang session error: {e}")
            return False


# =============================================================================
# ENCRYPTION HANDSHAKE HANDLER
# =============================================================================

class EncryptionHandler:
    """Handles the encryption handshake with the server."""

    def __init__(self, server_socket, auth_data: dict):
        self.server_socket = server_socket
        self.auth_data = auth_data
        self.packet_reader = PacketReader(compression_threshold=-1)

    def perform_handshake(self):
        """
        Perform encryption handshake with server.
        
        Returns:
            tuple: (socket, compression_threshold) on success
            - For encrypted servers: (EncryptedSocketWrapper, threshold)
            - For offline servers: (raw_socket, threshold)
            Returns None on failure.
        """
        while True:
            data = self.server_socket.recv(4096)
            if not data:
                return None
            
            self.packet_reader.add_data(data)
            packet_id, payload, _ = self.packet_reader.read_packet()
            
            if packet_id is None:
                continue

            if packet_id == 0x01 and payload is not None:  # Encryption Request
                return self._handle_encryption_request(payload)
            elif packet_id == 0x02:  # Login Success (offline mode, no compression)
                print("[INFO] Server is offline mode (no encryption, no compression)")
                return self.server_socket, -1
            elif packet_id == 0x03:  # Set Compression (offline mode with compression)
                threshold, _ = read_varint(payload, 0)
                threshold = threshold if threshold else -1
                print(f"[INFO] Server is offline mode with compression (threshold={threshold})")
                # Wait for Login Success after Set Compression
                return self._wait_for_login_success_offline(threshold)

    def _handle_encryption_request(self, payload: bytes):
        """Process Encryption Request and establish encrypted connection."""
        print("[CRYPTO] Encryption Request received")

        # Parse Encryption Request
        offset = 0
        server_id, offset = read_string(payload, offset)
        pubkey_length, offset = read_varint(payload, offset)
        if pubkey_length is None:
            return None
        public_key = payload[offset:offset + pubkey_length]
        offset += pubkey_length
        verify_length, offset = read_varint(payload, offset)
        if verify_length is None:
            return None
        verify_token = payload[offset:offset + verify_length]

        print(f"[CRYPTO] Server ID: '{server_id}'")
        print(f"[CRYPTO] Public Key: {len(public_key)} bytes")

        # Generate shared secret
        shared_secret = generate_shared_secret()
        print(f"[CRYPTO] Shared Secret: {shared_secret.hex()[:16]}...")

        # Compute server hash and validate with Mojang
        server_hash = compute_server_hash(server_id, shared_secret, public_key)
        print(f"[CRYPTO] Server Hash: {server_hash}")
        print("[CRYPTO] Validating session with Mojang...")

        if not MojangSessionValidator.join_server(
            self.auth_data['access_token'],
            self.auth_data['uuid'],
            server_hash
        ):
            return None

        # Send Encryption Response
        encrypted_secret = encrypt_with_public_key(public_key, shared_secret)
        encrypted_verify = encrypt_with_public_key(public_key, verify_token)

        response_payload = (
            write_varint(len(encrypted_secret)) + encrypted_secret +
            write_varint(len(encrypted_verify)) + encrypted_verify
        )
        self.server_socket.sendall(build_packet(0x01, response_payload))
        print("[CRYPTO] Encryption Response sent")

        # Enable AES encryption
        encrypted_socket = EncryptedSocketWrapper(self.server_socket, shared_secret)
        print("[CRYPTO] AES encryption enabled!")

        # Wait for Set Compression and Login Success
        return self._wait_for_login_success(encrypted_socket)

    def _wait_for_login_success(self, encrypted_socket):
        """Wait for Set Compression and Login Success packets after encryption."""
        print("[DEBUG] Waiting for post-encryption packets...")
        
        packet_reader = PacketReader(compression_threshold=-1)
        compression_threshold = -1

        while True:
            try:
                data = encrypted_socket.recv(4096)
                if not data:
                    print("[!] Connection lost during login")
                    return None
                packet_reader.add_data(data)
            except Exception as e:
                print(f"[!] Recv error after encryption: {e}")
                return None

            while packet_reader.has_data():
                # Update compression for packet reader
                packet_reader.compression_threshold = compression_threshold
                packet_id, payload, _ = packet_reader.read_packet()
                
                if packet_id is None:
                    break

                if packet_id == 0x03:  # Set Compression
                    threshold, _ = read_varint(payload, 0)
                    compression_threshold = threshold if threshold else -1
                    print(f"[CRYPTO] Set Compression (threshold={compression_threshold})")
                elif packet_id == 0x02:  # Login Success
                    print("[CRYPTO] Login Success!")
                    return encrypted_socket, compression_threshold
                elif packet_id == 0x00:  # Disconnect
                    try:
                        reason, _ = read_string(payload, 0)
                        print(f"[!] Disconnected during login: {reason}")
                    except:
                        print("[!] Disconnected during login")
                    return None

    def _wait_for_login_success_offline(self, compression_threshold: int):
        """
        Wait for Login Success packet in offline mode (after Set Compression).
        
        In offline mode, after receiving Set Compression, server sends Login Success.
        We need to wait for it before returning.
        """
        print("[DEBUG] Waiting for Login Success (offline mode)...")
        
        # Update packet reader to handle compression
        self.packet_reader.compression_threshold = compression_threshold

        while True:
            try:
                data = self.server_socket.recv(4096)
                if not data:
                    print("[!] Connection lost during offline login")
                    return None
                self.packet_reader.add_data(data)
            except Exception as e:
                print(f"[!] Recv error during offline login: {e}")
                return None

            while self.packet_reader.has_data():
                packet_id, payload, _ = self.packet_reader.read_packet()
                
                if packet_id is None:
                    break

                if packet_id == 0x02:  # Login Success
                    print("[INFO] Login Success (offline mode)!")
                    return self.server_socket, compression_threshold
                elif packet_id == 0x00:  # Disconnect
                    try:
                        reason, _ = read_string(payload, 0)
                        print(f"[!] Disconnected during offline login: {reason}")
                    except:
                        print("[!] Disconnected during offline login")
                    return None


# =============================================================================
# PACKET FORWARDER
# =============================================================================

class PacketForwarder:
    """Handles bidirectional packet forwarding between client and server."""

    def __init__(self, tracker: EntityTracker, position_store: PlayerPositionStore,
                 server_host: str, server_port: int):
        self.tracker = tracker
        self.position_store = position_store
        self.server_host = server_host
        self.server_port = server_port

    def forward_client_to_server(self, client_socket, server_socket, connection_state: dict):
        """Forward packets from client to server, parsing position updates."""
        is_first_packet = True
        compression_threshold = connection_state.get('compression_threshold', -1)

        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break

                # Rewrite first packet (Handshake) in handshaking phase
                if is_first_packet and connection_state['phase'] == 'handshaking':
                    data = rewrite_handshake(data, self.server_host, self.server_port)
                    is_first_packet = False
                    self._detect_next_state(data, connection_state)

                # Extract username from Login Start
                if connection_state['phase'] == 'login' and 'username' not in connection_state:
                    self._try_extract_username(data, connection_state)

                # Parse client position packets in play phase
                if connection_state['phase'] == 'play':
                    compression_threshold = connection_state.get('compression_threshold', -1)
                    self._parse_client_position_packet(data, compression_threshold)

                server_socket.sendall(data)

            except Exception as e:
                print(f"\n[!] Error C->S: {e}")
                break

        self._close_sockets(client_socket, server_socket)

    def forward_server_to_client(self, server_socket, client_socket, connection_state: dict):
        """Forward packets from server to client, parsing entity positions."""
        packet_reader = PacketReader(connection_state.get('compression_threshold', -1))

        while True:
            try:
                data = server_socket.recv(4096)
                if not data:
                    break

                packet_reader.add_data(data)

                # Parse complete packets from buffer
                while packet_reader.has_data():
                    packet_reader.compression_threshold = connection_state.get('compression_threshold', -1)
                    packet_id, payload, raw_packet = packet_reader.read_packet()
                    
                    if packet_id is None:
                        break

                    # Handle login phase packets
                    if connection_state['phase'] == 'login' and payload is not None:
                        self._handle_login_packet(packet_id, payload, connection_state)

                    # Parse play phase packets for entity positions
                    if connection_state['phase'] == 'play' and payload is not None:
                        self._parse_server_position_packet(packet_id, payload)

                client_socket.sendall(data)

            except Exception as e:
                print(f"\n[!] Error S->C: {e}")
                break

        self._close_sockets(server_socket, client_socket)

    def _detect_next_state(self, data: bytes, connection_state: dict):
        """Detect next_state from handshake packet."""
        try:
            offset = 0
            packet_length, offset = read_varint(data, offset)
            if packet_length:
                payload = data[offset:offset + packet_length]
                parse_offset = 0
                _, parse_offset = read_varint(payload, parse_offset)  # Packet ID
                _, parse_offset = read_varint(payload, parse_offset)  # Protocol version
                _, parse_offset = read_string(payload, parse_offset)  # Server address
                parse_offset += 2  # Port
                next_state, _ = read_varint(payload, parse_offset)
                connection_state['phase'] = 'status' if next_state == 1 else 'login'
        except:
            pass

    def _try_extract_username(self, data: bytes, connection_state: dict):
        """Try to extract username from Login Start packet."""
        try:
            offset = 0
            packet_length, offset = read_varint(data, offset)
            if packet_length and 0 < packet_length < 50:
                packet_id, payload_offset = read_varint(data, offset)
                if packet_id == 0x00:
                    username, _ = read_string(data, payload_offset)
                    if username and 3 <= len(username) <= 16:
                        if all(c.isalnum() or c == '_' for c in username):
                            connection_state['username'] = username
                            print(f"[LOGIN] Player: {username}")
        except:
            pass

    def _parse_client_position_packet(self, data: bytes, compression_threshold: int):
        """Parse client position packets (0x04, 0x05, 0x06)."""
        try:
            packet_reader = PacketReader(compression_threshold)
            packet_reader.add_data(data)
            packet_id, payload, _ = packet_reader.read_packet()
            
            if packet_id in [0x04, 0x05, 0x06] and payload is not None:
                result = parse_client_packet(packet_id, payload)
                if result:
                    self.position_store.update_my_position(
                        x=result.get('x'),
                        y=result.get('y'),
                        z=result.get('z'),
                        yaw=result.get('yaw'),
                        pitch=result.get('pitch')
                    )
        except:
            pass

    def _handle_login_packet(self, packet_id: int, payload: bytes, connection_state: dict):
        """Handle login phase packets."""
        if packet_id == 0x01:  # Encryption Request
            print("[!] ENCRYPTION REQUEST - Server is NOT offline mode!")
        elif packet_id == 0x03:  # Set Compression
            threshold, _ = read_varint(payload, 0)
            compression_threshold = threshold if threshold else -1
            connection_state['compression_threshold'] = compression_threshold
            print(f"[INFO] Compression enabled (threshold={compression_threshold})")
        elif packet_id == 0x02:  # Login Success
            connection_state['phase'] = 'play'
            username = connection_state.get('username', 'unknown')
            print(f"[OK] Connected as {username} - Tracking active")

    def _parse_server_position_packet(self, packet_id: int, payload: bytes):
        """Parse server packets for entity positions."""
        if packet_id not in PACKET_IDS:
            return

        try:
            result = parse_server_packet(packet_id, payload)
            if not result:
                return

            packet_type = result['type']

            if packet_type == 'spawn_player':
                self.tracker.on_spawn_player(
                    result['entity_id'],
                    result['x'], result['y'], result['z'],
                    result.get('uuid', 'unknown')
                )
            elif packet_type == 'teleport':
                self.tracker.on_entity_teleport(
                    result['entity_id'],
                    result['x'], result['y'], result['z']
                )
            elif packet_type in ['position_delta', 'position_rotation_delta']:
                self.tracker.on_entity_move(
                    result['entity_id'],
                    result['dx'], result['dy'], result['dz']
                )
            elif packet_type == 'my_position':
                yaw = result.get('yaw')
                pitch = result.get('pitch')
                self.tracker.on_my_position(
                    result['x'], result['y'], result['z'],
                    yaw if yaw is not None else 0.0,
                    pitch if pitch is not None else 0.0
                )
        except:
            pass

    @staticmethod
    def _close_sockets(*sockets):
        """Close multiple sockets safely."""
        for sock in sockets:
            try:
                sock.close()
            except:
                pass


# =============================================================================
# MINECRAFT PROXY
# =============================================================================

class MinecraftProxy:
    """Main proxy class that coordinates client connections and components."""

    def __init__(self, local_host: str, local_port: int, server_host: str, server_port: int):
        self.local_host = local_host
        self.local_port = local_port
        self.server_host = server_host
        self.server_port = server_port
        
        # Initialize components
        self.position_store = PlayerPositionStore()
        self.tracker = EntityTracker(self.position_store)
        self.forwarder = PacketForwarder(
            self.tracker, self.position_store, server_host, server_port
        )
        
        self.server_socket: socket.socket | None = None
        self.running = False

    def handle_client(self, client_socket, client_address):
        """Handle a single client connection."""
        print(f"\n[+] New connection from {client_address}")

        # Authenticate if online mode
        auth_data = None
        if ONLINE_MODE:
            auth_data = self._authenticate()
            if not auth_data:
                client_socket.close()
                return

        # Connect to real server
        server_socket = self._connect_to_server()
        if not server_socket:
            client_socket.close()
            return

        connection_state = {'phase': 'handshaking', 'encrypted': False}

        # Handle online mode authentication
        if ONLINE_MODE and auth_data:
            server_socket = self._handle_online_mode_login(
                client_socket, server_socket, auth_data, connection_state
            )
            if not server_socket:
                client_socket.close()
                return

        # Start forwarding threads
        client_to_server = threading.Thread(
            target=self.forwarder.forward_client_to_server,
            args=(client_socket, server_socket, connection_state),
            daemon=True
        )
        server_to_client = threading.Thread(
            target=self.forwarder.forward_server_to_client,
            args=(server_socket, client_socket, connection_state),
            daemon=True
        )

        client_to_server.start()
        server_to_client.start()
        client_to_server.join()
        server_to_client.join()

        print(f"\n[-] Connection closed for {client_address}")
        self._print_session_summary()

    def _authenticate(self):
        """Authenticate with Microsoft/Mojang."""
        print("[*] Online Mode - Authentication required")
        try:
            auth = MinecraftAuth()
            auth_data = auth.authenticate()
            print(f"[OK] Authenticated: {auth_data['username']}")
            return auth_data
        except Exception as e:
            print(f"[!] Authentication failed: {e}")
            return None

    def _connect_to_server(self):
        """Connect to the real Minecraft server."""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((self.server_host, self.server_port))
            server_socket.settimeout(None)
            print(f"[+] Connected to server {self.server_host}:{self.server_port}")
            return server_socket
        except Exception as e:
            print(f"[!] Cannot connect to server: {e}")
            return None

    def _handle_online_mode_login(self, client_socket, server_socket, auth_data, connection_state):
        """Handle the online mode login process."""
        client_data = client_socket.recv(4096)
        if not client_data:
            return None

        next_state = self._parse_handshake_next_state(client_data)

        if next_state == 1:
            # Status ping - transparent passthrough
            rewritten = rewrite_handshake(client_data, self.server_host, self.server_port)
            server_socket.sendall(rewritten)
            connection_state['phase'] = 'status'
            return server_socket

        # Login flow
        handshake_packet, trailing_data = self._split_handshake_data(client_data)
        rewritten = rewrite_handshake(handshake_packet, self.server_host, self.server_port)
        server_socket.sendall(rewritten)
        connection_state['phase'] = 'login'

        # Get and process Login Start
        login_data = trailing_data if trailing_data else client_socket.recv(4096)
        if login_data:
            self._log_client_username(login_data)
            self._send_authenticated_login_start(server_socket, auth_data)

        # Handle encryption/login handshake
        encryption_handler = EncryptionHandler(server_socket, auth_data)
        result = encryption_handler.perform_handshake()

        if result is None:
            print("[!] Handshake failed")
            return None
        
        result_socket, compression_threshold = result
        connection_state['phase'] = 'play'
        connection_state['compression_threshold'] = compression_threshold
        
        # Check if we got an encrypted socket (online mode) or raw socket (offline mode)
        if isinstance(result_socket, EncryptedSocketWrapper):
            connection_state['encrypted'] = True
            print("[OK] Encrypted handshake complete - Play mode active")
        else:
            connection_state['encrypted'] = False
            print("[OK] Offline mode handshake complete - Play mode active")

        # Send Set Compression and Login Success to client
        self._send_login_success_to_client(client_socket, auth_data, compression_threshold)
        return result_socket

    def _parse_handshake_next_state(self, data: bytes) -> int:
        """Parse next_state from handshake packet."""
        try:
            offset = 0
            packet_length, offset = read_varint(data, offset)
            if packet_length is None:
                return 2
            payload = data[offset:offset + packet_length]
            parse_offset = 0
            _, parse_offset = read_varint(payload, parse_offset)  # Packet ID
            _, parse_offset = read_varint(payload, parse_offset)  # Protocol
            _, parse_offset = read_string(payload, parse_offset)  # Address
            parse_offset += 2  # Port
            next_state, _ = read_varint(payload, parse_offset)
            return next_state if next_state is not None else 2
        except:
            return 2

    def _split_handshake_data(self, data: bytes):
        """Split handshake packet from trailing data."""
        offset = 0
        packet_length, offset = read_varint(data, offset)
        if packet_length is None:
            return data, b""
        handshake_end = offset + packet_length
        return data[:handshake_end], data[handshake_end:]

    def _log_client_username(self, login_data: bytes):
        """Log the username from client's Login Start packet."""
        try:
            offset = 0
            packet_length, offset = read_varint(login_data, offset)
            packet_id, payload_offset = read_varint(login_data, offset)
            if packet_id == 0x00:
                username, _ = read_string(login_data, payload_offset)
                print(f"[LOGIN] Client connecting as: {username}")
        except:
            pass

    def _send_authenticated_login_start(self, server_socket, auth_data: dict):
        """Send Login Start packet with authenticated username."""
        username = str(auth_data['username'])
        login_payload = write_string(username)
        server_socket.sendall(build_packet(0x00, login_payload))
        print(f"[LOGIN] Sent Login Start: {username}")

    def _send_login_success_to_client(self, client_socket, auth_data: dict, compression_threshold: int):
        """Send Set Compression and Login Success packets to client."""
        # Send Set Compression if needed
        if compression_threshold >= 0:
            compression_payload = write_varint(compression_threshold)
            client_socket.sendall(build_packet(0x03, compression_payload))
            print(f"[PROXY] Sent Set Compression to client (threshold={compression_threshold})")

        # Build Login Success packet
        uuid_str = str(auth_data['uuid'])
        uuid_formatted = f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:]}"
        username = str(auth_data['username'])

        login_success_payload = write_string(uuid_formatted) + write_string(username)

        if compression_threshold >= 0:
            login_success_packet = build_compressed_packet(0x02, login_success_payload, compression_threshold)
        else:
            login_success_packet = build_packet(0x02, login_success_payload)

        client_socket.sendall(login_success_packet)
        print(f"[PROXY] Sent Login Success to client ({username})")

    def _print_session_summary(self):
        """Print summary of detected players at end of session."""
        players = self.position_store.get_all_players()
        if players:
            print("\n[SUMMARY] Players detected:")
            for entity_id, data in players.items():
                print(f"  ID={entity_id}: X={data['x']:.1f} Y={data['y']:.1f} Z={data['z']:.1f}")

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
            
            # Clean up shared memory to avoid memory leaks
            self.position_store.cleanup()
            
            if self.server_socket is not None:
                try:
                    self.server_socket.close()
                except Exception:
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
                    handler = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
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
