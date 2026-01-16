import ctypes
from ctypes import wintypes
import struct
import time

# --- CONFIGURATION ---
PROCESS_NAME = "javaw.exe"
# Ta signature choisie (convertie en bytes)
SIGNATURE = bytes.fromhex("e52d062013000000000000000000f03f")

class MinecraftLive:
    def __init__(self):
        self.k32 = ctypes.windll.kernel32
        self.k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.handle = self._get_handle(PROCESS_NAME)
        self.player_address = None

    def _get_handle(self, name):
        import os
        tasks = os.popen(f'tasklist /FI "IMAGENAME eq {name}"').read()
        pid = int(tasks.splitlines()[3].split()[1])
        return self.k32.OpenProcess(0x1F0FFF, False, pid)

    def find_player_by_sig(self):
        print("[*] Recherche du joueur en RAM via signature...")
        address = 0
        mbi = self._get_mbi_structure()
        
        while self.k32.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == 0x1000 and mbi.Protect == 0x04: # MEM_COMMIT & READWRITE
                buf = (ctypes.c_char * mbi.RegionSize)()
                if self.k32.ReadProcessMemory(self.handle, mbi.BaseAddress, buf, mbi.RegionSize, None):
                    offset = buf.raw.find(SIGNATURE)
                    if offset != -1:
                        # L'adresse du joueur commence APRES la signature (16 octets)
                        self.player_address = mbi.BaseAddress + offset + 16
                        print(f"[+] JOUEUR TROUVÉ : {hex(self.player_address)}")
                        return True
            address += mbi.RegionSize
        return False

    def read_player_pos(self):
        buf = (ctypes.c_char * 24)() # 3 doubles = 24 octets
        self.k32.ReadProcessMemory(self.handle, self.player_address, buf, 24, None)
        return struct.unpack('<ddd', buf)

    def _get_mbi_structure(self):
        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                        ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                        ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]
        return MBI()

# --- EXECUTION ---
bot = MinecraftLive()
if bot.find_player_by_sig():
    try:
        while True:
            x, y, z = bot.read_player_pos()
            print(f"LIVE POS -> X: {x:.2f} | Y: {y:.2f} | Z: {z:.2f}      ", end="\r")
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\n[*] Arrêt.")