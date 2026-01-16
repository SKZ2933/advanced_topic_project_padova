"""
SNIFFER MINECRAFT - CAPTURE TRANSPARENTE
=========================================
Capture les paquets réseau entre Minecraft et le serveur
SANS avoir besoin de modifier l'adresse du serveur.

Prérequis :
1. Installer Npcap : https://npcap.com/#download
2. Installer Scapy : pip install scapy

Lancer EN ADMIN !
"""

from scapy.all import sniff, TCP, IP, Raw
import struct
import threading
import time
from collections import defaultdict
from mc_protocol import read_varint, parse_packet, PACKET_IDS

# ============================================================
# CONFIGURATION
# ============================================================
SERVER_HOST = "SKZ33.aternos.me"  # Le serveur Minecraft
SERVER_PORT = 25565
# ============================================================

class TCPStreamReassembler:
    """Réassemble les flux TCP pour avoir des paquets Minecraft complets"""
    def __init__(self):
        self.streams = defaultdict(lambda: {'buffer': b'', 'seq': None})
    
    def add_packet(self, src, dst, seq, payload):
        key = (src, dst)
        stream = self.streams[key]
        
        # Ajouter les données au buffer
        stream['buffer'] += payload
        return self.extract_minecraft_packets(key)
    
    def extract_minecraft_packets(self, key):
        """Extrait les paquets Minecraft complets du buffer"""
        stream = self.streams[key]
        packets = []
        
        while len(stream['buffer']) > 0:
            # Essayer de lire la longueur
            length, length_size = read_varint(stream['buffer'], 0)
            if length is None:
                break
            
            total_size = length_size + length
            if len(stream['buffer']) < total_size:
                break  # Paquet incomplet
            
            # Extraire le paquet complet
            packet = stream['buffer'][:total_size]
            stream['buffer'] = stream['buffer'][total_size:]
            packets.append(packet)
        
        return packets


class MinecraftSniffer:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.server_ip = None
        self.reassembler = TCPStreamReassembler()
        self.entities = {}  # entity_id -> {x, y, z}
        self.compression_enabled = False
        
    def resolve_server(self):
        """Résout l'adresse IP du serveur"""
        import socket
        try:
            self.server_ip = socket.gethostbyname(self.server_host)
            print(f"[+] Serveur résolu : {self.server_host} -> {self.server_ip}")
            return True
        except:
            print(f"[!] Impossible de résoudre {self.server_host}")
            return False
    
    def process_packet(self, pkt):
        """Traite un paquet capturé"""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        payload = bytes(pkt[Raw])
        
        # Déterminer la direction
        if ip_layer.src == self.server_ip and tcp_layer.sport == self.server_port:
            direction = "S->C"
            key_src = f"{ip_layer.src}:{tcp_layer.sport}"
            key_dst = f"{ip_layer.dst}:{tcp_layer.dport}"
        elif ip_layer.dst == self.server_ip and tcp_layer.dport == self.server_port:
            direction = "C->S"
            key_src = f"{ip_layer.src}:{tcp_layer.sport}"
            key_dst = f"{ip_layer.dst}:{tcp_layer.dport}"
        else:
            return
        
        # Réassembler les paquets TCP
        mc_packets = self.reassembler.add_packet(key_src, key_dst, tcp_layer.seq, payload)
        
        # Analyser chaque paquet Minecraft
        for mc_packet in mc_packets:
            self.analyze_packet(mc_packet, direction)
    
    def analyze_packet(self, data, direction):
        """Analyse un paquet Minecraft"""
        if direction != "S->C":
            return
        
        offset = 0
        length, offset = read_varint(data, offset)
        if length is None:
            return
        
        packet_data = data[offset:]
        offset = 0
        
        # Lire l'ID du paquet
        packet_id, offset = read_varint(packet_data, offset)
        if packet_id is None:
            return
        
        # Parser les paquets de position
        if packet_id in PACKET_IDS:
            result = parse_packet(packet_id, packet_data[offset:])
            if result:
                self.handle_position(result)
    
    def handle_position(self, result):
        """Traite une info de position"""
        if result['type'] == 'spawn_player':
            self.entities[result['entity_id']] = {
                'x': result['x'],
                'y': result['y'],
                'z': result['z'],
                'uuid': result.get('uuid', 'unknown')
            }
            print(f"\n[SPAWN] Joueur ID={result['entity_id']} @ ({result['x']:.2f}, {result['y']:.2f}, {result['z']:.2f})")
        
        elif result['type'] == 'teleport':
            self.entities[result['entity_id']] = {
                'x': result['x'],
                'y': result['y'],
                'z': result['z']
            }
            print(f"\n[TELEPORT] ID={result['entity_id']:4d} @ X={result['x']:8.2f} Y={result['y']:6.2f} Z={result['z']:8.2f}")
        
        elif result['type'] in ['position_delta', 'position_rotation_delta']:
            if result['entity_id'] in self.entities:
                ent = self.entities[result['entity_id']]
                ent['x'] += result['dx']
                ent['y'] += result['dy']
                ent['z'] += result['dz']
                print(f"\r[MOVE] ID={result['entity_id']:4d} @ X={ent['x']:8.2f} Y={ent['y']:6.2f} Z={ent['z']:8.2f}   ", end="")
    
    def start(self):
        """Démarre la capture"""
        if not self.resolve_server():
            return
        
        print(f"\n[*] Capture des paquets vers/depuis {self.server_ip}:{self.server_port}")
        print("[*] Lancez Minecraft et connectez-vous au serveur normalement.")
        print("[*] Appuyez sur Ctrl+C pour arrêter.\n")
        
        # Filtre BPF pour capturer uniquement le trafic du serveur
        bpf_filter = f"tcp and host {self.server_ip} and port {self.server_port}"
        
        try:
            sniff(filter=bpf_filter, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            print("\n\n[*] Capture arrêtée.")
            self.show_summary()
    
    def show_summary(self):
        """Affiche un résumé des entités trackées"""
        print("\n" + "="*60)
        print("RÉSUMÉ DES ENTITÉS TRACKÉES")
        print("="*60)
        for eid, data in self.entities.items():
            print(f"  ID={eid:4d} : X={data['x']:8.2f} Y={data['y']:6.2f} Z={data['z']:8.2f}")


def main():
    print("="*60)
    print("SNIFFER MINECRAFT - CAPTURE TRANSPARENTE")
    print("="*60)
    print("\n[!] Ce script doit être lancé EN ADMINISTRATEUR")
    print("[!] Prérequis : Npcap installé + pip install scapy\n")
    
    sniffer = MinecraftSniffer(SERVER_HOST, SERVER_PORT)
    sniffer.start()


if __name__ == "__main__":
    main()
