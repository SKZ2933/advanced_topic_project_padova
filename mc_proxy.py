"""
PROXY MINECRAFT 1.8.9 - INTERCEPTION DES POSITIONS
===================================================
Proxy TCP qui s'intercale entre le client et le serveur pour
intercepter les paquets de position des joueurs.

SUPPORTE ONLINE-MODE:
- Authentification Microsoft/Mojang
- Chiffrement AES-128-CFB8

Configuration :
- LOCAL_PORT : Port sur lequel le proxy écoute
- SERVER_HOST : Serveur Minecraft cible
- SERVER_PORT : Port du serveur (généralement 25565)
- ONLINE_MODE : True pour serveurs premium, False pour cracked
"""

import socket
import threading
import zlib
import struct
import time
import requests
from mc_protocol import read_varint, write_varint, parse_packet, parse_client_packet, PACKET_IDS, read_string, read_float, read_double, read_ubyte
from auth_microsoft import MinecraftAuth
from mc_crypto import generate_shared_secret, encrypt_with_public_key, compute_server_hash, EncryptedSocketWrapper

# ============================================================
# SHARED DATA FOR AIMBOT
# ============================================================
import json
import os

# Fichier JSON pour communication inter-processus avec l'aimbot
SHARED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aimbot_data.json")

shared_data = {
    'my_position': {'x': 0, 'y': 0, 'z': 0, 'yaw': 0, 'pitch': 0},
    'players': {},  # entity_id -> {x, y, z, uuid}
    'lock': threading.Lock()
}

def export_to_file():
    """Exporte les données vers le fichier JSON pour l'aimbot"""
    try:
        with shared_data['lock']:
            data = {
                'my_position': shared_data['my_position'].copy(),
                'players': {str(k): v for k, v in shared_data['players'].items()}
            }
        with open(SHARED_FILE, 'w') as f:
            json.dump(data, f)
    except:
        pass  # Ignorer les erreurs d'écriture

# ============================================================
# CONFIGURATION
# ============================================================
LOCAL_HOST = "0.0.0.0"
LOCAL_PORT = 25566
SERVER_HOST = "mc.dikingvps.com"
SERVER_PORT = 25565
ONLINE_MODE = True  # True = serveur premium (authentification requise)
# ============================================================


class EntityTracker:
    """Suit les positions des JOUEURS uniquement"""
    def __init__(self):
        self.players = {}  # entity_id -> {x, y, z, uuid}
        self.my_entity_id = None
    
    def add_player(self, entity_id, x, y, z, uuid):
        """Ajoute un joueur (appelé uniquement sur Spawn Player 0x0C)"""
        self.players[entity_id] = {'x': x, 'y': y, 'z': z, 'uuid': uuid}
        return self.players[entity_id]
    
    def update_position_delta(self, entity_id, dx, dy, dz):
        """Met à jour position delta - seulement si c'est un joueur"""
        if entity_id in self.players:
            self.players[entity_id]['x'] += dx
            self.players[entity_id]['y'] += dy
            self.players[entity_id]['z'] += dz
            return self.players[entity_id]
        return None  # Ignorer les non-joueurs
    
    def set_position(self, entity_id, x, y, z):
        """Met à jour position absolue - seulement si c'est un joueur"""
        if entity_id in self.players:
            self.players[entity_id]['x'] = x
            self.players[entity_id]['y'] = y
            self.players[entity_id]['z'] = z
            return self.players[entity_id]
        return None  # Ignorer les non-joueurs
    
    def remove_player(self, entity_id):
        if entity_id in self.players:
            del self.players[entity_id]
    
    def is_player(self, entity_id):
        return entity_id in self.players
    
    def get_all_players(self):
        return self.players


def write_string(s):
    """Écrit une string Minecraft (VarInt length + UTF-8)"""
    encoded = s.encode('utf-8')
    return write_varint(len(encoded)) + encoded


def rewrite_handshake(packet_data, target_host, target_port):
    """
    Réécrit le paquet Handshake pour remplacer l'adresse du serveur.
    IMPORTANT: Conserve les données qui suivent le Handshake (ex: Status Request)
    
    Format Handshake (ID 0x00 en Handshaking state):
    - VarInt: Protocol Version
    - String: Server Address  <-- On remplace ça !
    - Unsigned Short: Server Port  <-- On remplace ça aussi !
    - VarInt: Next State (1=Status, 2=Login)
    """
    offset = 0
    
    # Lire la longueur du paquet
    packet_length, offset = read_varint(packet_data, offset)
    if packet_length is None:
        return packet_data  # Retourner tel quel si erreur
    
    handshake_end = offset + packet_length  # Position après le Handshake
    trailing_data = packet_data[handshake_end:]  # Données après le Handshake (Status Request, etc.)
    
    payload = packet_data[offset:handshake_end]
    offset = 0
    
    # Lire l'ID du paquet
    packet_id, offset = read_varint(payload, offset)
    if packet_id != 0x00:
        return packet_data  # Pas un handshake
    
    # Lire Protocol Version
    protocol_version, offset = read_varint(payload, offset)
    
    # Lire Server Address (on l'ignore, on va le remplacer)
    server_addr, offset = read_string(payload, offset)
    
    # Lire Server Port
    if offset + 2 > len(payload):
        return packet_data
    server_port = struct.unpack('>H', payload[offset:offset + 2])[0]
    offset += 2
    
    # Lire Next State
    next_state, offset = read_varint(payload, offset)
    
    # Debug désactivé pour réduire le bruit
    # print(f"[HANDSHAKE] {server_addr}:{server_port} -> {target_host}:{target_port}")
    
    # Reconstruire le paquet avec la nouvelle adresse
    new_payload = write_varint(0x00)  # Packet ID
    new_payload += write_varint(protocol_version)
    new_payload += write_string(target_host)  # Nouvelle adresse !
    new_payload += struct.pack('>H', target_port)  # Nouveau port !
    new_payload += write_varint(next_state)
    
    # Ajouter la longueur du paquet + les données qui suivaient
    new_packet = write_varint(len(new_payload)) + new_payload + trailing_data
    
    return new_packet


class MinecraftProxy:
    """Proxy Minecraft avec réécriture du Handshake"""
    
    def __init__(self, local_host, local_port, server_host, server_port):
        self.local_host = local_host
        self.local_port = local_port
        self.server_host = server_host
        self.server_port = server_port
        self.tracker = EntityTracker()
    
    def handle_packet(self, data, direction, compression_threshold):
        """Analyse un paquet et extrait les infos de position"""
        offset = 0
        
        # Lire la longueur du paquet
        packet_length, offset = read_varint(data, offset)
        if packet_length is None:
            return
        
        packet_data = data[offset:offset + packet_length]
        offset = 0
        
        # Si compression activée
        if compression_threshold >= 0:
            data_length, offset = read_varint(packet_data, offset)
            if data_length and data_length > 0:
                try:
                    packet_data = zlib.decompress(packet_data[offset:])
                    offset = 0
                except:
                    return
        
        # Lire l'ID du paquet
        packet_id, offset = read_varint(packet_data, offset)
        if packet_id is None:
            return
        
        # Parser les paquets de position (server -> client seulement)
        if direction == "S->C" and packet_id in PACKET_IDS:
            try:
                result = parse_packet(packet_id, packet_data[offset:])
                if result:
                    self.process_position(result)
            except Exception as e:
                pass  # Ignorer les erreurs de parsing
    
    def process_position(self, result):
        """Traite les infos de position - JOUEURS UNIQUEMENT"""
        if result['type'] == 'spawn_player':
            # Seul paquet qui identifie un JOUEUR (pas un mob)
            ent = self.tracker.add_player(
                result['entity_id'],
                result['x'], result['y'], result['z'],
                result.get('uuid', 'unknown')
            )
            uuid_short = result.get('uuid', '?')[:8]
            print(f"\n>>> JOUEUR DÉTECTÉ: ID={result['entity_id']} UUID={uuid_short}...")
            print(f"    Position: X={result['x']:.1f} Y={result['y']:.1f} Z={result['z']:.1f}")
            
            # Sync to shared_data for aimbot
            with shared_data['lock']:
                shared_data['players'][result['entity_id']] = {
                    'x': result['x'], 'y': result['y'], 'z': result['z'],
                    'uuid': result.get('uuid', 'unknown')
                }
        
        elif result['type'] == 'teleport':
            # Ne tracker que si c'est un joueur connu
            ent = self.tracker.set_position(
                result['entity_id'],
                result['x'], result['y'], result['z']
            )
            if ent:  # ent est None si ce n'est pas un joueur
                print(f"\r[JOUEUR {result['entity_id']:3d}] X={result['x']:8.1f} Y={result['y']:5.1f} Z={result['z']:8.1f}  ", end="", flush=True)
                # Sync to shared_data
                with shared_data['lock']:
                    if result['entity_id'] in shared_data['players']:
                        shared_data['players'][result['entity_id']].update({
                            'x': result['x'], 'y': result['y'], 'z': result['z']
                        })
        
        elif result['type'] in ['position_delta', 'position_rotation_delta']:
            # Ne tracker que si c'est un joueur connu
            ent = self.tracker.update_position_delta(
                result['entity_id'],
                result['dx'], result['dy'], result['dz']
            )
            if ent:  # ent est None si ce n'est pas un joueur
                print(f"\r[JOUEUR {result['entity_id']:3d}] X={ent['x']:8.1f} Y={ent['y']:5.1f} Z={ent['z']:8.1f}  ", end="", flush=True)
                # Sync to shared_data
                with shared_data['lock']:
                    if result['entity_id'] in shared_data['players']:
                        shared_data['players'][result['entity_id']].update({
                            'x': ent['x'], 'y': ent['y'], 'z': ent['z']
                        })
        
        elif result['type'] == 'my_position':
            # Position du joueur local
            with shared_data['lock']:
                shared_data['my_position'].update({
                    'x': result['x'], 'y': result['y'], 'z': result['z'],
                    'yaw': result.get('yaw', 0), 'pitch': result.get('pitch', 0)
                })
        
        # Exporter les données vers le fichier pour l'aimbot
        export_to_file()
    
    def forward_client_to_server(self, client_socket, server_socket, state):
        """Transmet les données du client vers le serveur"""
        buffer = b""
        first_packet = True
        compression_threshold = state.get('compression_threshold', -1)
        print(f"[DEBUG] forward_client_to_server démarré (compression={compression_threshold}, phase={state['phase']})")
        
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Si c'est le premier paquet (Handshake), le réécrire
                if first_packet and state['phase'] == 'handshaking':
                    data = rewrite_handshake(data, self.server_host, self.server_port)
                    first_packet = False
                    
                    # Déterminer le next_state pour le suivi
                    # Parser le paquet Handshake réécrit pour extraire next_state
                    offset = 0
                    plen, offset = read_varint(data, offset)
                    if plen:
                        payload = data[offset:offset+plen]
                        p_offset = 0
                        # Packet ID (0x00)
                        _, p_offset = read_varint(payload, p_offset)
                        # Protocol version
                        _, p_offset = read_varint(payload, p_offset)
                        # Server address (string)
                        addr, p_offset = read_string(payload, p_offset)
                        # Server port (2 bytes)
                        p_offset += 2
                        # Next state
                        next_state, _ = read_varint(payload, p_offset)
                        if next_state == 1:
                            state['phase'] = 'status'
                        else:
                            state['phase'] = 'login'
                
                # Parser le Login Start pour extraire le username (une seule fois)
                if state['phase'] == 'login' and 'username' not in state:
                    try:
                        offset = 0
                        plen, offset = read_varint(data, offset)
                        if plen and plen > 0 and plen < 50:  # Login Start fait moins de 50 bytes
                            pid, poffset = read_varint(data, offset)
                            if pid == 0x00:  # Login Start packet
                                # Le username est une string juste après le packet ID
                                name, _ = read_string(data, poffset)
                                # Valider que c'est un vrai username Minecraft (3-16 chars, alphanum + _)
                                if name and 3 <= len(name) <= 16:
                                    valid = all(c.isalnum() or c == '_' for c in name)
                                    if valid:
                                        state['username'] = name
                                        print(f"[LOGIN] Joueur: {name}")
                    except:
                        pass
                
                # Parser les paquets client en phase Play pour tracker l'orientation
                if state['phase'] == 'play':
                    try:
                        compression_threshold = state.get('compression_threshold', -1)
                        offset = 0
                        plen, offset = read_varint(data, offset)
                        if plen and plen > 0:
                            packet_data = data[offset:offset + plen]
                            p_offset = 0
                            
                            # Gérer la compression si activée
                            if compression_threshold >= 0:
                                data_length, p_offset = read_varint(packet_data, p_offset)
                                if data_length and data_length > 0:
                                    # Paquet compressé - décompresser
                                    try:
                                        packet_data = zlib.decompress(packet_data[p_offset:])
                                        p_offset = 0
                                    except:
                                        pass  # Échec décompression, essayer sans
                            
                            # Lire l'ID du paquet
                            pid, p_offset = read_varint(packet_data, p_offset)
                            
                            # Packets 0x04 (Player Position), 0x05 (Player Look), 0x06 (Player Position And Look)
                            if pid in [0x04, 0x05, 0x06]:
                                result = parse_client_packet(pid, packet_data[p_offset:])
                                if result:
                                    with shared_data['lock']:
                                        # Mettre à jour la position si disponible
                                        if 'x' in result:
                                            shared_data['my_position']['x'] = result['x']
                                            shared_data['my_position']['y'] = result['y']
                                            shared_data['my_position']['z'] = result['z']
                                        # Mettre à jour l'orientation si disponible
                                        if 'yaw' in result:
                                            shared_data['my_position']['yaw'] = result['yaw']
                                            shared_data['my_position']['pitch'] = result['pitch']
                                    export_to_file()
                    except:
                        pass
                
                # Transmettre au serveur
                server_socket.sendall(data)
                
            except Exception as e:
                print(f"\n[!] Erreur C->S: {e}")
                break
        
        try:
            client_socket.close()
            server_socket.close()
        except:
            pass
    
    def forward_server_to_client(self, server_socket, client_socket, state):
        """Transmet les données du serveur vers le client et analyse les paquets"""
        buffer = b""
        # Récupérer le seuil de compression depuis state (peut être déjà défini après handshake chiffré)
        compression_threshold = state.get('compression_threshold', -1)
        print(f"[DEBUG] forward_server_to_client démarré (compression={compression_threshold}, phase={state['phase']})")
        
        while True:
            try:
                data = server_socket.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                # Essayer de parser les paquets complets
                while len(buffer) > 0:
                    try:
                        length, length_size = read_varint(buffer, 0)
                        if length is None or len(buffer) < length_size + length:
                            break  # Paquet incomplet
                        
                        packet = buffer[:length_size + length]
                        buffer = buffer[length_size + length:]
                        
                        # Détecter les paquets en phase login
                        if state['phase'] == 'login':
                            offset = length_size
                            
                            # Si compression activée, décompresser le paquet
                            if compression_threshold >= 0:
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
                                    print("[!] ENCRYPTION REQUEST - Le serveur n'est PAS en mode offline!")
                                elif pid == 0x03:  # Set Compression
                                    threshold, _ = read_varint(packet, offset)
                                    compression_threshold = threshold if threshold else -1
                                    state['compression_threshold'] = compression_threshold  # Stocker dans state
                                    print(f"[INFO] Compression activée (seuil={compression_threshold})")
                                elif pid == 0x02:  # Login Success
                                    state['phase'] = 'play'
                                    username = state.get('username', 'inconnu')
                                    print(f"[OK] Connecté en tant que {username} - Tracking actif")
                        
                        # Analyser le paquet si en mode Play
                        if state['phase'] == 'play':
                            try:
                                self.handle_packet(packet, "S->C", compression_threshold)
                            except:
                                pass
                        
                    except:
                        break
                
                # Transmettre au client
                client_socket.sendall(data)
                
            except Exception as e:
                print(f"\n[!] Erreur S->C: {e}")
                break
        
        try:
            server_socket.close()
            client_socket.close()
        except:
            pass
    
    def handle_encryption_handshake(self, server_socket, auth_data):
        """
        Gère le handshake de chiffrement avec le serveur.
        
        1. Reçoit Encryption Request du serveur
        2. Génère shared secret et le chiffre avec RSA
        3. Valide la session auprès de Mojang
        4. Envoie Encryption Response
        5. Active le chiffrement AES
        
        Returns:
            EncryptedSocketWrapper ou None si échec
        """
        # Buffer pour recevoir les paquets
        buffer = b""
        
        while True:
            data = server_socket.recv(4096)
            if not data:
                return None
            buffer += data
            
            # Lire la longueur du paquet
            offset = 0
            packet_length, offset = read_varint(buffer, offset)
            if packet_length is None or len(buffer) < offset + packet_length:
                continue  # Paquet incomplet
            
            packet_data = buffer[offset:offset + packet_length]
            buffer = buffer[offset + packet_length:]
            
            # Lire l'ID du paquet
            p_offset = 0
            packet_id, p_offset = read_varint(packet_data, p_offset)
            
            if packet_id == 0x01:  # Encryption Request
                print("[CRYPTO] Encryption Request reçu")
                
                # Parser le paquet
                # String: Server ID
                server_id, p_offset = read_string(packet_data, p_offset)
                
                # VarInt + bytes: Public Key
                pubkey_len, p_offset = read_varint(packet_data, p_offset)
                public_key = packet_data[p_offset:p_offset + pubkey_len]
                p_offset += pubkey_len
                
                # VarInt + bytes: Verify Token
                verify_len, p_offset = read_varint(packet_data, p_offset)
                verify_token = packet_data[p_offset:p_offset + verify_len]
                
                print(f"[CRYPTO] Server ID: '{server_id}'")
                print(f"[CRYPTO] Public Key: {len(public_key)} bytes")
                
                # Générer le shared secret
                shared_secret = generate_shared_secret()
                print(f"[CRYPTO] Shared Secret généré: {shared_secret.hex()[:16]}...")
                
                # Calculer le server hash pour Mojang
                server_hash = compute_server_hash(server_id, shared_secret, public_key)
                print(f"[CRYPTO] Server Hash: {server_hash}")
                
                # Joindre la session Mojang
                print("[CRYPTO] Validation session Mojang...")
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
                        print("[CRYPTO] Session Mojang validée!")
                    else:
                        print(f"[!] Erreur session Mojang: {response.status_code} {response.text}")
                        return None
                except Exception as e:
                    print(f"[!] Erreur session Mojang: {e}")
                    return None
                
                # Chiffrer le shared secret et verify token avec RSA
                encrypted_secret = encrypt_with_public_key(public_key, shared_secret)
                encrypted_verify = encrypt_with_public_key(public_key, verify_token)
                
                # Construire et envoyer Encryption Response (0x01)
                response_payload = write_varint(0x01)  # Packet ID
                response_payload += write_varint(len(encrypted_secret))
                response_payload += encrypted_secret
                response_payload += write_varint(len(encrypted_verify))
                response_payload += encrypted_verify
                
                response_packet = write_varint(len(response_payload)) + response_payload
                server_socket.sendall(response_packet)
                print("[CRYPTO] Encryption Response envoyé")
                
                # Activer le chiffrement AES
                encrypted_socket = EncryptedSocketWrapper(server_socket, shared_secret)
                print("[CRYPTO] Chiffrement AES activé!")
                
                # Maintenant recevoir Set Compression et Login Success (chiffrés)
                # et les transmettre au client (en clair car le client ne chiffre pas)
                login_complete = False
                compression_threshold = -1
                
                print("[DEBUG] En attente des paquets post-encryption...")
                print("[DEBUG] En attente des paquets post-encryption...")
                while not login_complete:
                    try:
                        # Si le buffer est vide, lire du socket
                        if not buffer:
                            enc_data = encrypted_socket.recv(4096)
                            if not enc_data:
                                print("[!] Connexion perdue pendant login (recv vide)")
                                return None
                            buffer += enc_data
                    except Exception as e:
                        print(f"[!] Erreur recv après encryption: {e}")
                        return None
                    
                    while len(buffer) > 0:
                        offset = 0
                        # Lire la longueur du paquet
                        plen, offset = read_varint(buffer, offset)
                        
                        if plen is None or len(buffer) < offset + plen:
                            # Paquet incomplet, on a besoin de plus de data
                            try:
                                more_data = encrypted_socket.recv(4096)
                                if not more_data: return None
                                buffer += more_data
                                continue
                            except:
                                return None
                        
                        # Extraire le paquet complet
                        packet = buffer[:offset + plen]
                        buffer = buffer[offset + plen:]
                        
                        # Parser le contenu du paquet
                        # Attention: 'offset' était l'index dans 'buffer'. 
                        # Pour 'packet', le contenu commence à l'index 'offset' (après Length VarInt)
                        p_offset = offset
                        
                        # Gérer la compression si activée
                        if compression_threshold >= 0:
                            data_len, p_offset = read_varint(packet, p_offset)
                            
                            if data_len > 0:
                                # Paquet compressé
                                try:
                                    decompressed = zlib.decompress(packet[p_offset:])
                                    # Le paquet décompressé contient: PacketID + Data
                                    packet_content = decompressed
                                    p_offset = 0 # Reset offset pour le contenu décompressé
                                except Exception as e:
                                    print(f"[!] Erreur décompression: {e}")
                                    return None
                            else:
                                # Paquet non compressé (Data Length = 0)
                                packet_content = packet
                                # p_offset pointe déjà après DataLen, c'est bon
                                pass
                        else:
                            # Pas de compression
                            packet_content = packet
                        
                        # Lire le Packet ID
                        if compression_threshold >= 0 and data_len > 0:
                             # Depuis le buffer décompressé
                             pid, new_off = read_varint(packet_content, p_offset)
                             p_offset = new_off
                             payload = packet_content
                        else:
                             # Depuis le paquet brut
                             pid, new_off = read_varint(packet_content, p_offset)
                             payload = packet_content
                             p_offset = new_off
                        
                        if pid == 0x03:  # Set Compression
                            threshold, _ = read_varint(payload, p_offset)
                            compression_threshold = threshold if threshold else -1
                            print(f"[CRYPTO] Set Compression reçu (seuil={compression_threshold})")
                            
                        elif pid == 0x02:  # Login Success
                            print("[CRYPTO] Login Success reçu!")
                            login_complete = True
                            
                        elif pid == 0x00:  # Disconnect
                            try:
                                reason, _ = read_string(payload, p_offset)
                                print(f"[!] Déconnexion pendant login: {reason}")
                            except:
                                print(f"[!] Déconnexion pendant login (raison illisible)")
                            return None
                        else:
                            # Ignorer les autres paquets (Plugin Message, etc)
                            pass
                
                return encrypted_socket, compression_threshold
            
            elif packet_id == 0x02:  # Login Success (pas de chiffrement demandé)
                print("[INFO] Serveur en mode offline (pas de chiffrement)")
                return None
            
            elif packet_id == 0x03:  # Set Compression (avant encryption)
                threshold, _ = read_varint(packet_data, p_offset)
                print(f"[INFO] Set Compression (pas de chiffrement): {threshold}")
                return None
    
    def handle_client(self, client_socket, address):
        """Gère une connexion client"""
        print(f"\n[+] Nouvelle connexion de {address}")
        
        # Authentification si mode online
        auth_data = None
        if ONLINE_MODE:
            print("[*] Mode Online - Authentification requise")
            try:
                auth = MinecraftAuth()
                auth_data = auth.authenticate()
                print(f"[OK] Authentifié: {auth_data['username']}")
            except Exception as e:
                print(f"[!] Échec authentification: {e}")
                client_socket.close()
                return
        
        # Se connecter au vrai serveur
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((self.server_host, self.server_port))
            server_socket.settimeout(None)
            print(f"[+] Connecté au serveur {self.server_host}:{self.server_port}")
        except Exception as e:
            print(f"[!] Impossible de joindre le serveur: {e}")
            client_socket.close()
            return
        
        # État partagé pour suivre la phase de connexion
        state = {'phase': 'handshaking', 'encrypted': False}
        
        # En mode online, on doit gérer le handshake spécialement
        if ONLINE_MODE and auth_data:
            print("[DEBUG] Mode online - début du handshake manuel")
            # Recevoir le Handshake du client et le transmettre
            client_data = client_socket.recv(4096)
            print(f"[DEBUG] Reçu du client: {len(client_data) if client_data else 0} bytes")
            
            if client_data:
                # Parser pour déterminer next_state (1=Status/ping, 2=Login)
                try:
                    offset = 0
                    plen, offset = read_varint(client_data, offset)
                    payload = client_data[offset:offset+plen]
                    p_offset = 0
                    pid, p_offset = read_varint(payload, p_offset)  # Packet ID (0x00)
                    proto_ver, p_offset = read_varint(payload, p_offset)  # Protocol version
                    addr, p_offset = read_string(payload, p_offset)  # Server address
                    p_offset += 2  # Port (2 bytes)
                    next_state, _ = read_varint(payload, p_offset)  # Next state
                    print(f"[DEBUG] Handshake: next_state={next_state} ({'Status/Ping' if next_state == 1 else 'Login'})")
                except Exception as e:
                    print(f"[DEBUG] Erreur parsing handshake: {e}")
                    next_state = 2  # Assume login
                
                # Si c'est un ping (status), passer en mode transparent (pas d'auth)
                if next_state == 1:
                    print("[DEBUG] Mode Status - passage transparent (pas d'auth)")
                    # Réécrire le handshake et transmettre
                    rewritten = rewrite_handshake(client_data, self.server_host, self.server_port)
                    server_socket.sendall(rewritten)
                    state['phase'] = 'status'
                    # Continuer avec les threads normaux pour le status
                else:
                    # C'est un login - faire l'authentification complète
                    # Le client peut envoyer Handshake + Login Start dans le même buffer
                    # Extraire le handshake et voir s'il y a un Login Start après
                    handshake_len = offset + plen  # Taille totale du paquet Handshake
                    remaining_data = client_data[handshake_len:]  # Données après le Handshake
                    
                    # Réécrire et envoyer le handshake
                    handshake_packet = client_data[:handshake_len]
                    rewritten = rewrite_handshake(handshake_packet, self.server_host, self.server_port)
                    server_socket.sendall(rewritten)
                    print("[DEBUG] Handshake Login envoyé au serveur")
                    state['phase'] = 'login'
                    
                    # Vérifier si Login Start est déjà dans le buffer
                    if remaining_data:
                        login_data = remaining_data
                        print(f"[DEBUG] Login Start déjà dans le buffer ({len(login_data)} bytes)")
                    else:
                        # Recevoir le Login Start du client
                        print("[DEBUG] En attente du Login Start du client...")
                        login_data = client_socket.recv(4096)
                    
                    if login_data:
                        # Parser pour extraire le username du client
                        try:
                            loffset = 0
                            lplen, loffset = read_varint(login_data, loffset)
                            pid, poffset = read_varint(login_data, loffset)
                            if pid == 0x00:
                                name, _ = read_string(login_data, poffset)
                                print(f"[LOGIN] Client se connecte comme: {name}")
                        except Exception as e:
                            print(f"[DEBUG] Erreur parsing Login Start: {e}")
                        
                        # Transmettre le Login Start (avec le vrai username du compte)
                        real_username = auth_data['username']
                        login_payload = write_varint(0x00)  # Login Start packet ID
                        login_payload += write_varint(len(real_username.encode('utf-8')))
                        login_payload += real_username.encode('utf-8')
                        login_packet = write_varint(len(login_payload)) + login_payload
                        server_socket.sendall(login_packet)
                        print(f"[LOGIN] Envoyé Login Start: {real_username}")
                    
                    # Gérer le handshake de chiffrement
                    result = self.handle_encryption_handshake(server_socket, auth_data)
                    
                    if result:
                        encrypted_server_socket, compression_threshold = result
                        state['encrypted'] = True
                        state['phase'] = 'play'
                        state['compression_threshold'] = compression_threshold
                        
                        # Utiliser le socket chiffré pour la suite
                        server_socket = encrypted_server_socket
                        
                        # Envoyer Set Compression au client si nécessaire
                        if compression_threshold >= 0:
                            comp_payload = write_varint(0x03)  # Set Compression packet ID
                            comp_payload += write_varint(compression_threshold)
                            comp_packet = write_varint(len(comp_payload)) + comp_payload
                            client_socket.sendall(comp_packet)
                            print(f"[PROXY] Envoyé Set Compression au client (seuil={compression_threshold})")
                        
                        # Envoyer Login Success au client
                        # Format: UUID (string), Username (string)
                        uuid_str = auth_data['uuid']
                        # Formater UUID avec tirets
                        uuid_formatted = f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:]}"
                        username = auth_data['username']
                        
                        login_success_payload = write_varint(0x02)  # Login Success packet ID
                        login_success_payload += write_varint(len(uuid_formatted)) + uuid_formatted.encode('utf-8')
                        login_success_payload += write_varint(len(username)) + username.encode('utf-8')
                        
                        # Si compression activée, wrapper le paquet
                        if compression_threshold >= 0:
                            # Paquet non compressé (data_length = 0)
                            inner = write_varint(0) + login_success_payload
                            login_success_packet = write_varint(len(inner)) + inner
                        else:
                            login_success_packet = write_varint(len(login_success_payload)) + login_success_payload
                        
                        client_socket.sendall(login_success_packet)
                        print(f"[PROXY] Envoyé Login Success au client ({username})")
                        
                        print("[OK] Handshake chiffré terminé - Mode Play actif")
                    else:
                        # Mode offline ou erreur - continuer sans chiffrement
                        print("[INFO] Continuant sans chiffrement")
                        pass
        
        # Stocker le socket serveur dans state pour les threads
        state['server_socket'] = server_socket
        state['client_socket'] = client_socket
        
        # Threads pour transmettre dans les deux sens
        t1 = threading.Thread(target=self.forward_client_to_server, args=(client_socket, state['server_socket'], state))
        t2 = threading.Thread(target=self.forward_server_to_client, args=(state['server_socket'], client_socket, state))
        
        t1.daemon = True
        t2.daemon = True
        
        t1.start()
        t2.start()
        
        t1.join()
        t2.join()
        
        print(f"\n[-] Connexion fermée pour {address}")
        
        # Afficher le résumé des joueurs trackés
        players = self.tracker.get_all_players()
        if players:
            print("\n[RÉSUMÉ] Joueurs détectés:")
            for eid, data in players.items():
                print(f"  ID={eid}: X={data['x']:.1f} Y={data['y']:.1f} Z={data['z']:.1f}")
    
    def start(self):
        """Démarre le proxy"""
        print("=" * 60)
        print("PROXY MINECRAFT 1.8.9 - INTERCEPTION DES POSITIONS")
        print("=" * 60)
        print(f"\n[*] Configuration:")
        print(f"    Écoute sur : {self.local_host}:{self.local_port}")
        print(f"    Serveur    : {self.server_host}:{self.server_port}")
        print(f"\n[*] Dans Minecraft, connectez-vous à : localhost:{self.local_port}")
        print("=" * 60)
        
        # Créer le socket serveur
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.local_host, self.local_port))
        server.listen(5)
        
        print(f"\n[+] Proxy en écoute sur le port {self.local_port}...")
        print("[*] En attente de connexion Minecraft...\n")
        
        try:
            while True:
                client_socket, address = server.accept()
                handler = threading.Thread(target=self.handle_client, args=(client_socket, address))
                handler.daemon = True
                handler.start()
        except KeyboardInterrupt:
            print("\n[*] Arrêt du proxy.")
            server.close()


def main():
    proxy = MinecraftProxy(LOCAL_HOST, LOCAL_PORT, SERVER_HOST, SERVER_PORT)
    proxy.start()


if __name__ == "__main__":
    main()
