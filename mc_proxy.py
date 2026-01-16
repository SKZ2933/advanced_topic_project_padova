"""
PROXY MINECRAFT 1.8.9 - INTERCEPTION DES POSITIONS
===================================================
Proxy TCP qui s'intercale entre le client et le serveur pour
intercepter les paquets de position des joueurs.

SOLUTION AU PROBLÈME DE HANDSHAKE :
Le paquet Handshake envoyé par le client contient "localhost"
mais le serveur attend l'adresse réelle. Ce proxy réécrit 
le paquet Handshake pour corriger l'adresse.

Configuration :
- LOCAL_PORT : Port sur lequel le proxy écoute
- SERVER_HOST : Serveur Minecraft cible
- SERVER_PORT : Port du serveur (généralement 25565)
"""

import socket
import threading
import zlib
import struct
import time
from mc_protocol import read_varint, write_varint, parse_packet, PACKET_IDS, read_string

# ============================================================
# CONFIGURATION
# ============================================================
LOCAL_HOST = "0.0.0.0"
LOCAL_PORT = 25566
SERVER_HOST = "SKZ33.aternos.me"
SERVER_PORT = 50048
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
        
        elif result['type'] == 'teleport':
            # Ne tracker que si c'est un joueur connu
            ent = self.tracker.set_position(
                result['entity_id'],
                result['x'], result['y'], result['z']
            )
            if ent:  # ent est None si ce n'est pas un joueur
                print(f"\r[JOUEUR {result['entity_id']:3d}] X={result['x']:8.1f} Y={result['y']:5.1f} Z={result['z']:8.1f}  ", end="", flush=True)
        
        elif result['type'] in ['position_delta', 'position_rotation_delta']:
            # Ne tracker que si c'est un joueur connu
            ent = self.tracker.update_position_delta(
                result['entity_id'],
                result['dx'], result['dy'], result['dz']
            )
            if ent:  # ent est None si ce n'est pas un joueur
                print(f"\r[JOUEUR {result['entity_id']:3d}] X={ent['x']:8.1f} Y={ent['y']:5.1f} Z={ent['z']:8.1f}  ", end="", flush=True)
    
    def forward_client_to_server(self, client_socket, server_socket, state):
        """Transmet les données du client vers le serveur"""
        buffer = b""
        first_packet = True
        
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
        compression_threshold = -1
        
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
    
    def handle_client(self, client_socket, address):
        """Gère une connexion client"""
        print(f"\n[+] Nouvelle connexion de {address}")
        
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
        state = {'phase': 'handshaking'}
        
        # Threads pour transmettre dans les deux sens
        t1 = threading.Thread(target=self.forward_client_to_server, args=(client_socket, server_socket, state))
        t2 = threading.Thread(target=self.forward_server_to_client, args=(server_socket, client_socket, state))
        
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
