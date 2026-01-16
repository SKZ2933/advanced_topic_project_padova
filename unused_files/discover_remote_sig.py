"""
MONITORING DE COORDONNÉE UNIQUE
================================
Stratégie :
1. Trouver TOUS les X correspondant à la valeur de B
2. Les monitorer en continu
3. Quand B bouge, voir lesquels changent pour correspondre à la nouvelle valeur
4. Cette adresse = position X de B

On ne cherche PAS Y et Z ensemble !
"""

import ctypes
from ctypes import wintypes
import struct
import os
import time

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

class SingleCoordMonitor:
    def __init__(self):
        self.k32 = ctypes.windll.kernel32
        self.k32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, 
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.handle = None

    def connect(self, pid):
        self.handle = self.k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return self.handle is not None

    def find_all_matching(self, target, tolerance=0.5):
        """Trouve TOUTES les adresses contenant cette valeur"""
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
                        
                        # Double
                        for i in range(0, len(data) - 8, 4):
                            try:
                                val = struct.unpack_from('<d', data, i)[0]
                                if abs(val - target) < tolerance:
                                    results.append({'addr': base + i, 'val': val, 'fmt': 'd'})
                            except: pass
                        
                        # Float
                        for i in range(0, len(data) - 4, 4):
                            try:
                                val = struct.unpack_from('<f', data, i)[0]
                                if abs(val - target) < tolerance:
                                    results.append({'addr': base + i, 'val': val, 'fmt': 'f'})
                            except: pass
                            
            address = (mbi.BaseAddress or 0) + mbi.RegionSize
        
        return results

    def read_value(self, addr, fmt='d'):
        size = 8 if fmt == 'd' else 4
        buf = (ctypes.c_char * size)()
        if self.k32.ReadProcessMemory(self.handle, ctypes.c_void_p(addr), buf, size, None):
            return struct.unpack(f'<{fmt}', buf)[0]
        return None


def main():
    print("="*70)
    print("MONITORING DE COORDONNÉE UNIQUE (X)")
    print("="*70)
    
    pids = []
    tasks = os.popen('tasklist /FI "IMAGENAME eq javaw.exe" /NH').read().splitlines()
    for line in tasks:
        parts = line.split()
        if len(parts) > 1 and parts[1].isdigit():
            pids.append(int(parts[1]))

    print(f"\n[*] Instances Minecraft :")
    for i, p in enumerate(pids):
        print(f"  {i} : PID {p}")
    
    idx = int(input("\nIndex instance A : "))
    
    monitor = SingleCoordMonitor()
    if not monitor.connect(pids[idx]):
        print("[!] Connexion échouée")
        return
    
    print(f"[+] Connecté au PID {pids[idx]}")
    
    # Obtenir X de B
    print("\n" + "-"*70)
    x_b = float(input("Coordonnée X de B (juste X) : "))
    
    # Trouver tous les X
    print(f"\n[*] Recherche de toutes les valeurs proches de {x_b}...")
    results = monitor.find_all_matching(x_b, tolerance=1.0)
    print(f"[+] {len(results)} adresses trouvées")
    
    if not results:
        print("[!] Aucune valeur trouvée.")
        return
    
    # Afficher les premiers
    print("\n[*] Premières adresses :")
    for i, r in enumerate(results[:20]):
        print(f"  {i}: {hex(r['addr'])} = {r['val']:.4f} ({r['fmt']})")
    
    # Monitoring en temps réel
    print("\n" + "="*70)
    print("MONITORING EN TEMPS RÉEL")
    print("="*70)
    print(">>> Bougez le joueur B maintenant ! <<<")
    print("Le script va détecter quelles adresses changent.")
    print("Appuyez sur Ctrl+C pour arrêter.\n")
    
    # Sauvegarder les valeurs initiales
    initial_values = {}
    for r in results:
        val = monitor.read_value(r['addr'], r['fmt'])
        if val is not None:
            initial_values[r['addr']] = {'val': val, 'fmt': r['fmt']}
    
    # Monitorer les changements
    try:
        changed_addresses = set()
        check_count = 0
        
        while True:
            check_count += 1
            new_changes = []
            
            for addr, info in initial_values.items():
                if addr in changed_addresses:
                    continue
                    
                current = monitor.read_value(addr, info['fmt'])
                if current is not None:
                    delta = abs(current - info['val'])
                    # Si la valeur a changé significativement
                    if delta > 0.5:
                        changed_addresses.add(addr)
                        new_changes.append({
                            'addr': addr,
                            'old': info['val'],
                            'new': current,
                            'fmt': info['fmt']
                        })
            
            # Afficher les nouvelles détections
            for c in new_changes:
                print(f"[!] CHANGEMENT @ {hex(c['addr'])} : {c['old']:.3f} -> {c['new']:.3f} ({c['fmt']})")
            
            # Statut
            if check_count % 20 == 0:
                print(f"[*] Cycle {check_count} - {len(changed_addresses)} adresse(s) ont changé", end="\r")
            
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        print(f"\n\n[*] Monitoring arrêté.")
        print(f"[*] {len(changed_addresses)} adresse(s) ont changé au total.")
        
        if changed_addresses:
            print("\n[***] ADRESSES QUI ONT CHANGÉ :")
            for addr in list(changed_addresses)[:10]:
                info = initial_values[addr]
                current = monitor.read_value(addr, info['fmt'])
                print(f"  {hex(addr)} : {info['val']:.3f} -> {current:.3f} ({info['fmt']})")
            
            # Sélection pour tracking
            print("\n" + "-"*70)
            target_hex = input("Entrez l'adresse à tracker (ex: 0x1234) ou 'q' : ")
            if target_hex.lower() == 'q':
                return
            
            target_addr = int(target_hex, 16)
            target_fmt = initial_values[target_addr]['fmt']
            
            # Tracking live
            print(f"\n[*] Tracking de {hex(target_addr)}... (Ctrl+C pour arrêter)")
            try:
                while True:
                    val = monitor.read_value(target_addr, target_fmt)
                    if val:
                        print(f"\rX = {val:.6f}   ", end="")
                    time.sleep(0.05)
            except KeyboardInterrupt:
                print("\n[*] Fin.")
                
                # Signature
                sig_buf = (ctypes.c_char * 16)()
                monitor.k32.ReadProcessMemory(monitor.handle, ctypes.c_void_p(target_addr - 16), sig_buf, 16, None)
                print(f"\n[+] SIGNATURE : {sig_buf.raw.hex()}")


if __name__ == "__main__":
    main()
