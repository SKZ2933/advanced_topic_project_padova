import ctypes
from ctypes import wintypes
import struct
import time
import math
import os

# --- STRUCTURES SYSTÈME ---
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

# --- CONFIGURATION ---
SIG_PLAYER = bytes.fromhex("e52d062013000000000000000000f03f")
SIG_ENTITY = bytes.fromhex("ec0e012013000000000000000000f03f")

class MinecraftAimbot:
    def __init__(self):
        self.k32 = ctypes.windll.kernel32
        self.k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        
        try:
            tasks = os.popen('tasklist /FI "IMAGENAME eq javaw.exe"').read()
            pid = int(tasks.splitlines()[3].split()[1])
            self.handle = self.k32.OpenProcess(0x1F0FFF, False, pid)
            print(f"[*] Connecté à Minecraft (PID: {pid})")
        except Exception as e:
            print(f"[!] Erreur de connexion : {e}")
            exit()

        self.my_addr = None
        self.entities = set()
        self.initial_rotation_data = None

    def scan_memory(self):
        """ Scanne la RAM pour trouver le joueur et les entités """
        print("[*] Scan de la mémoire en cours (peut durer 10-20s)...")
        address = 0
        mbi = MBI()
        new_entities = set()
        
        while self.k32.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == 0x1000 and mbi.Protect == 0x04:
                buf = (ctypes.c_char * mbi.RegionSize)()
                if self.k32.ReadProcessMemory(self.handle, mbi.BaseAddress, buf, mbi.RegionSize, None):
                    raw = buf.raw
                    
                    # 1. Trouver ton adresse
                    if not self.my_addr:
                        off = raw.find(SIG_PLAYER)
                        if off != -1:
                            self.my_addr = mbi.BaseAddress + off + 16
                            print(f"[+] Ton adresse trouvée : {hex(self.my_addr)}")

                    # 2. Trouver les entités (Mobs)
                    curr = 0
                    while True:
                        off = raw.find(SIG_ENTITY, curr)
                        if off == -1: break
                        addr = mbi.BaseAddress + off + 16
                        if addr != self.my_addr:
                            new_entities.add(addr)
                        curr = off + 1
            address += mbi.RegionSize
        self.entities = new_entities
        print(f"[*] Scan terminé. {len(self.entities)} entités en mémoire.")

    def read_double(self, addr):
        buf = ctypes.c_double()
        self.k32.ReadProcessMemory(self.handle, addr, ctypes.byref(buf), 8, None)
        return buf.value

    def hunt_rotation_offsets(self):
        """ Analyse 200 octets autour de ta position pour voir ce qui change quand tu tournes """
        if not self.my_addr: return
        
        buf = (ctypes.c_char * 200)()
        self.k32.ReadProcessMemory(self.handle, self.my_addr, buf, 200, None)
        # On lit 50 floats (4 octets chacun)
        current_floats = struct.unpack('<' + 'f' * 50, buf.raw)

        if self.initial_rotation_data is None:
            self.initial_rotation_data = current_floats
            return

        print("\n--- ANALYSE ROTATION (BOUGE TA SOURIS) ---")
        for i, val in enumerate(current_floats):
            diff = abs(val - self.initial_rotation_data[i])
            # Un angle change entre 0.1 et 360 degrés
            if 0.1 < diff < 360:
                offset = i * 4
                print(f"Offset {hex(offset)} : Valeur={val:.2f} (Delta={diff:.2f})")
        
        self.initial_rotation_data = current_floats

# --- BOUCLE D'EXÉCUTION ---
bot = MinecraftAimbot()
bot.scan_memory()

print("\n[*] Lancement du monitoring. Appuie sur Ctrl+C pour arrêter.")
try:
    while True:
        if bot.my_addr:
            # 1. Lecture de tes coordonnées
            mx = bot.read_double(bot.my_addr)
            my = bot.read_double(bot.my_addr + 8)
            mz = bot.read_double(bot.my_addr + 16)
            
            # 2. Affichage simple
            print(f"\rMOI: X:{mx:.1f} Y:{my:.1f} Z:{mz:.1f} | Mobs detectés: {len(bot.entities)}", end="")
            
            # 3. Chasse aux angles (Yaw/Pitch)
            bot.hunt_rotation_offsets()
            
            # 4. Lecture des Mobs (on limite l'affichage pour la clarté)
            for ent in list(bot.entities)[:3]: # Affiche seulement les 3 premiers
                tx = bot.read_double(ent)
                tz = bot.read_double(ent + 16)
                dist = math.sqrt((mx-tx)**2 + (mz-tz)**2)
                if 0.1 < dist < 50:
                    print(f"\n[MOB] Dist: {dist:.1f}m | Pos: {tx:.1f}, {tz:.1f}")

        time.sleep(0.2) # On ralentit un peu pour voir les offsets changer
except KeyboardInterrupt:
    print("\n[*] Arrêt du script.")