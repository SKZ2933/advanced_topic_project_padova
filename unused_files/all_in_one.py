import ctypes
import os
import struct
import time
from ctypes import wintypes

# --- CONSTANTES WINDOWS ---
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

class MinecraftScanner:
    def __init__(self):
        self.k32 = ctypes.windll.kernel32
        # On définit explicitement les types pour éviter les plantages 64 bits
        self.k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.handle = None
        self.pid = None

    def connect(self):
        pids = []
        tasks = os.popen('tasklist /FI "IMAGENAME eq javaw.exe" /NH').read().splitlines()
        
        for line in tasks:
            parts = line.split()
            if len(parts) > 1:
                pids.append(int(parts[1]))

        if not pids:
            print("[!] Erreur: Aucun Minecraft détecté.")
            return False

        if len(pids) > 1:
            print(f"\n[*] Plusieurs instances détectées :")
            for i, p in enumerate(pids):
                print(f"  {i} : PID {p}")
            
            # On te laisse choisir l'index (0, 1, etc.)
            choix = int(input("\nChoisissez l'index de VOTRE instance (ex: 1) : "))
            self.pid = pids[choix]
        else:
            self.pid = pids[0]

        self.handle = self.k32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not self.handle:
            print(f"[!] Erreur d'accès au PID {self.pid}. Lancez en ADMIN.")
            return False
            
        print(f"[+] Connecté à votre PID: {self.pid}")
        return True

    def get_memory_dump(self):
        chunks = {}
        address = 0
        mbi = MBI()
        # On limite le scan pour éviter de lire des zones inutiles ou protégées
        while self.k32.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            # On ne scanne que la mémoire allouée et accessible en lecture/écriture
            if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
                size = mbi.RegionSize
                if size < 100 * 1024 * 1024: # On ignore les blocs géants (>100Mo) pour la vitesse
                    buf = (ctypes.c_char * size)()
                    if self.k32.ReadProcessMemory(self.handle, mbi.BaseAddress, buf, size, None):
                        chunks[mbi.BaseAddress] = buf.raw
            address = (mbi.BaseAddress or 0) + mbi.RegionSize
        return chunks

    def find_candidates(self, dump, target_pos, tolerance=0.5):
        x_t, y_t, z_t = target_pos
        candidates = set()
        for base_addr, data in dump.items():
            # Pas de 4 octets pour attraper les doubles mal alignés (fréquent en Java)
            for i in range(0, len(data) - 24, 4):
                try:
                    x, y, z = struct.unpack_from('<ddd', data, i)
                    if abs(x - x_t) < tolerance and abs(z - z_t) < tolerance and abs(y - y_t) < 2.0:
                        candidates.add(base_addr + i)
                except: continue
        return candidates

def main():
    scanner = MinecraftScanner()
    if not scanner.connect(): return

    # --- ETAPE 1 ---
    print("\n--- ETAPE 1 : POINT A ---")
    pos1_str = input("Entrez vos coordonnées F3 (X Y Z) : ")
    pos1 = tuple(map(float, pos1_str.split()))
    
    dump1 = scanner.get_memory_dump()
    cand1 = scanner.find_candidates(dump1, pos1)
    print(f"[+] {len(cand1)} adresses trouvées.")

    # --- ETAPE 2 ---
    print("\n--- ETAPE 2 : POINT B ---")
    print("Bougez de quelques blocs...")
    pos2_str = input("Entrez vos nouvelles coordonnées F3 (X Y Z) : ")
    pos2 = tuple(map(float, pos2_str.split()))
    
    dump2 = scanner.get_memory_dump()
    cand2 = scanner.find_candidates(dump2, pos2)
    
    # --- ETAPE 3 : FILTRAGE ---
    # On cherche les adresses qui persistent
    final_candidates = cand1.intersection(cand2)
    
    if not final_candidates:
        print("[!] Aucun candidat stable. Essayez de bouger plus ou d'augmenter la tolérance.")
        return

    # On prend la première adresse valide (souvent la seule après intersection)
    player_addr = list(final_candidates)[0]
    print(f"\n[***] ADRESSE IDENTIFIÉE : {hex(player_addr)} [***]")
    
    # --- ETAPE 4 : LIVE ---
    print("\nRadar actif (Ctrl+C pour quitter)...")
    try:
        buf = (ctypes.c_char * 24)()
        while True:
            if scanner.k32.ReadProcessMemory(scanner.handle, ctypes.c_void_p(player_addr), buf, 24, None):
                x, y, z = struct.unpack('<ddd', buf)
                print(f" LIVE -> X: {x:8.2f} | Y: {y:8.2f} | Z: {z:8.2f}", end="\r")
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\n[*] Fin du tracking.")

if __name__ == "__main__":
    main()