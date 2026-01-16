import ctypes, struct, os, math
from ctypes import wintypes

# Ta signature de joueur (tronquée pour être plus générique aux entités)
# On cherche le pattern de la structure de position qui est commun à tous les joueurs
SIG_ENTITY_BASE = bytes.fromhex("000000000000f03f") 

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD)]

def get_my_pos(h, my_addr):
    buf = (ctypes.c_char * 24)()
    ctypes.windll.kernel32.ReadProcessMemory(h, ctypes.c_void_p(my_addr), buf, 24, None)
    return struct.unpack('<ddd', buf)

def scan_for_players():
    k32 = ctypes.windll.kernel32
    pid = int(os.popen('tasklist /FI "IMAGENAME eq javaw.exe"').read().splitlines()[3].split()[1])
    h = k32.OpenProcess(0x1F0FFF, False, pid)
    
    my_addr = 0x8e610f78 # Ton adresse joueur actuelle
    mx, my, mz = get_my_pos(h, my_addr)
    
    print(f"[*] Ta position : {mx:.1f}, {my:.1f}, {mz:.1f}")
    print("[*] Scan des entités aux alentours...")

    mbi = MBI()
    addr = 0
    targets = []

    while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        # On scanne la mémoire de type "Private" (0x20000) ou "Image"
        if mbi.State == 0x1000 and (mbi.Protect == 0x04 or mbi.Protect == 0x40):
            size = mbi.RegionSize
            if 0 < size < 100 * 1024 * 1024:
                buf = (ctypes.c_char * size)()
                if k32.ReadProcessMemory(h, mbi.BaseAddress, buf, size, None):
                    curr = 0
                    while True:
                        # On cherche le marqueur de structure f03f
                        off = buf.raw.find(SIG_ENTITY_BASE, curr)
                        if off == -1: break
                        
                        # Adresse potentielle (on ajuste l'offset selon ta signature)
                        ent_addr = (mbi.BaseAddress if mbi.BaseAddress else 0) + off - 8
                        
                        if ent_addr != my_addr:
                            # On lit les coordonnées XYZ du candidat
                            try:
                                # On lit 24 octets pour avoir X, Y, Z (3 Doubles)
                                c_buf = buf.raw[off-8 : off+16]
                                tx, ty, tz = struct.unpack('<ddd', c_buf)
                                
                                # FILTRE CRUCIAL : Distance
                                dist = math.sqrt((mx-tx)**2 + (my-ty)**2 + (mz-tz)**2)
                                
                                # Si c'est à moins de 100 blocs et pas à 0,0,0
                                if 0.5 < dist < 100 and abs(ty) < 256:
                                    print(f"[!] JOUEUR/MOB DÉTECTÉ : {hex(ent_addr)} | Dist: {dist:.1f}m")
                                    targets.append({'addr': ent_addr, 'dist': dist, 'pos': (tx, ty, tz)})
                            except: pass
                        curr = off + 8
        
        addr = (mbi.BaseAddress or 0) + mbi.RegionSize
        if addr > 0x7FFFFFFFFFFF: break

    return h, targets

h, targets = scan_for_players()