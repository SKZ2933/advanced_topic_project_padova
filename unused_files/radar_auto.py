"""
PHASE 2 : RADAR AUTOMATIQUE
============================
Ce script utilise la signature découverte en Phase 1 pour
trouver et tracker automatiquement tous les RemotePlayers.

IMPORTANT : Mettez à jour la variable REMOTE_SIGNATURE avec
la signature trouvée par discover_remote_sig.py
"""

import ctypes
from ctypes import wintypes
import struct
import time
import os
import math

# ============================================================
# CONFIGURATION - Mettez votre signature ici !
# ============================================================
# Copiez la signature trouvée par discover_remote_sig.py
REMOTE_SIGNATURE = bytes.fromhex("VOTRE_SIGNATURE_ICI")  # <-- À REMPLACER !

# Votre signature LocalPlayer (pour vous trouver aussi)
LOCAL_SIGNATURE = bytes.fromhex("e52d062013000000000000000000f03f")  # Peut changer !
# ============================================================

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class MinecraftRadar:
    def __init__(self):
        self.k32 = ctypes.windll.kernel32
        self.k32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, 
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.handle = None
        self.my_address = None
        self.remote_addresses = []

    def connect(self, pid):
        self.handle = self.k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return self.handle is not None

    def find_by_signature(self, signature):
        """Trouve toutes les adresses précédées de cette signature"""
        results = []
        address = 0
        mbi = MBI()
        
        while self.k32.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
                size = mbi.RegionSize
                if size < 100 * 1024 * 1024:
                    buf = (ctypes.c_char * size)()
                    if self.k32.ReadProcessMemory(self.handle, mbi.BaseAddress, buf, size, None):
                        data = buf.raw
                        base = mbi.BaseAddress
                        
                        offset = 0
                        while True:
                            pos = data.find(signature, offset)
                            if pos == -1:
                                break
                            # L'adresse des coords est APRÈS la signature (16 octets)
                            addr = base + pos + 16
                            results.append(addr)
                            offset = pos + 1
                            
            address = (mbi.BaseAddress or 0) + mbi.RegionSize
        
        return results

    def read_position(self, addr):
        """Lit une position double à l'adresse donnée"""
        buf = (ctypes.c_char * 24)()
        if self.k32.ReadProcessMemory(self.handle, ctypes.c_void_p(addr), buf, 24, None):
            try:
                return struct.unpack('<ddd', buf)
            except:
                return None
        return None

    def scan_all(self):
        """Scanne pour le LocalPlayer et les RemotePlayers"""
        # Chercher le LocalPlayer
        local_results = self.find_by_signature(LOCAL_SIGNATURE)
        if local_results:
            self.my_address = local_results[0]
            print(f"[+] LocalPlayer trouvé : {hex(self.my_address)}")
        else:
            print("[!] LocalPlayer non trouvé (signature incorrecte ?)")
            return False
        
        # Chercher les RemotePlayers
        self.remote_addresses = self.find_by_signature(REMOTE_SIGNATURE)
        print(f"[+] {len(self.remote_addresses)} RemotePlayer(s) trouvé(s)")
        
        for i, addr in enumerate(self.remote_addresses):
            pos = self.read_position(addr)
            if pos:
                print(f"    {i}: {hex(addr)} -> ({pos[0]:.1f}, {pos[1]:.1f}, {pos[2]:.1f})")
        
        return True

    def run_radar(self):
        """Boucle principale du radar"""
        print("\n[*] RADAR ACTIF (Ctrl+C pour arrêter)")
        print("-" * 70)
        
        try:
            while True:
                # Ma position
                my_pos = self.read_position(self.my_address)
                if not my_pos:
                    continue
                mx, my, mz = my_pos
                
                output = f"MOI: ({mx:.1f}, {my:.1f}, {mz:.1f})"
                
                # Positions des RemotePlayers
                for i, addr in enumerate(self.remote_addresses):
                    pos = self.read_position(addr)
                    if pos:
                        rx, ry, rz = pos
                        dist = math.sqrt((rx - mx)**2 + (rz - mz)**2)
                        output += f" | P{i}: ({rx:.1f}, {ry:.1f}, {rz:.1f}) [{dist:.0f}m]"
                
                print(f"\r{output}   ", end="")
                time.sleep(0.05)
                
        except KeyboardInterrupt:
            print("\n[*] Radar arrêté.")


def main():
    print("="*60)
    print("PHASE 2 : RADAR AUTOMATIQUE")
    print("="*60)
    
    # Vérifier que la signature a été configurée
    if REMOTE_SIGNATURE == bytes.fromhex("VOTRE_SIGNATURE_ICI"):
        print("\n[!] ERREUR : Vous devez d'abord configurer REMOTE_SIGNATURE !")
        print("    1. Exécutez discover_remote_sig.py pour trouver la signature")
        print("    2. Copiez la signature dans ce fichier (ligne 21)")
        
        # Essayer de charger depuis le fichier
        if os.path.exists("remote_player_signature.txt"):
            with open("remote_player_signature.txt", "r") as f:
                sig = f.read().strip()
            print(f"\n[*] Signature trouvée dans remote_player_signature.txt :")
            print(f'    REMOTE_SIGNATURE = bytes.fromhex("{sig}")')
        return
    
    # Lister les PIDs
    pids = []
    tasks = os.popen('tasklist /FI "IMAGENAME eq javaw.exe" /NH').read().splitlines()
    for line in tasks:
        parts = line.split()
        if len(parts) > 1 and parts[1].isdigit():
            pids.append(int(parts[1]))

    if not pids:
        print("[!] Aucun Minecraft détecté")
        return

    print(f"\n[*] Instances Minecraft :")
    for i, p in enumerate(pids):
        print(f"  {i} : PID {p}")
    
    idx = int(input("\nVotre instance : "))
    
    radar = MinecraftRadar()
    if not radar.connect(pids[idx]):
        print("[!] Connexion échouée. Lancez en admin.")
        return
    
    print(f"[+] Connecté au PID {pids[idx]}")
    
    # Scanner
    print("\n[*] Scan de la mémoire...")
    if not radar.scan_all():
        return
    
    # Radar
    radar.run_radar()


if __name__ == "__main__":
    main()
