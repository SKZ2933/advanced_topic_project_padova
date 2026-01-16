import ctypes
import struct
import os
import time

# --- CONFIG ---
TARGET_X = -166.96
TARGET_Z = 249.40
MY_PID = 19164 

class FloatScanner:
    def __init__(self, pid):
        self.k32 = ctypes.windll.kernel32
        self.handle = self.k32.OpenProcess(0x1F0FFF, False, pid)
        self.pid = pid

    def scan_floats(self):
        print(f"[*] Recherche de l'ami en mode 'FLOAT' (4 octets) dans le PID {self.pid}...")
        address = 0
        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", ctypes.c_uint32), ("PartitionId", ctypes.c_uint16),
                        ("RegionSize", ctypes.c_size_t), ("State", ctypes.c_uint32),
                        ("Protect", ctypes.c_uint32), ("Type", ctypes.c_uint32)]
        
        mbi = MBI()
        while self.k32.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == 0x1000 and mbi.Protect == 0x04:
                size = mbi.RegionSize
                if size < 150 * 1024 * 1024:
                    buf = (ctypes.c_char * size)()
                    if self.k32.ReadProcessMemory(self.handle, ctypes.c_void_p(mbi.BaseAddress), buf, size, None):
                        data = buf.raw
                        # On cherche des FLOAT (4 octets)
                        for i in range(0, len(data) - 12, 4):
                            try:
                                # On cherche X et Z côte à côte en float
                                x, y, z = struct.unpack_from('<fff', data, i)
                                if abs(x - TARGET_X) < 1.0 and abs(z - TARGET_Z) < 1.0:
                                    if 60 < y < 110:
                                        return mbi.BaseAddress + i, x, y, z
                            except: continue
            address = (mbi.BaseAddress or 0) + mbi.RegionSize
        return None

# --- RUN ---
scanner = FloatScanner(MY_PID)
result = scanner.scan_floats()

if result:
    addr, rx, ry, rz = result
    print(f"\n[***] AMI TROUVÉ EN FLOAT ! [***]")
    print(f"ADRESSE : {hex(addr)}")
    print(f"VALEURS : X:{rx:.2f} Y:{ry:.2f} Z:{rz:.2f}")
else:
    print("[!] Toujours rien en float. On va devoir scanner les objets par leur nom (AK2933) pour trouver l'adresse.")