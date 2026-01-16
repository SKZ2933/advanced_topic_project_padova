import ctypes, struct, os, math
from ctypes import wintypes

# Ta signature confirmée
SIG_PLAYER = bytes.fromhex("e52d062013000000000000000000f03f")
# On cherche cette partie commune aux entités (les 8 derniers octets)
SIG_COMMON = bytes.fromhex("000000000000f03f")

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD)]

def spider_scan():
    k32 = ctypes.windll.kernel32
    k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    
    pid = int(os.popen('tasklist /FI "IMAGENAME eq javaw.exe"').read().splitlines()[3].split()[1])
    h = k32.OpenProcess(0x1F0FFF, False, pid)
    
    my_addr = 0x8e610f78 # Ton adresse actuelle trouvée
    
    # On définit une zone de recherche de 10 Mo autour de toi
    search_range = 10 * 1024 * 1024 
    start_addr = my_addr - (search_range // 2)
    
    print(f"[*] Scan de voisinage autour de {hex(my_addr)}...")
    
    buf = (ctypes.c_char * search_range)()
    if k32.ReadProcessMemory(h, ctypes.c_void_p(start_addr), buf, search_range, None):
        raw = buf.raw
        curr = 0
        found_count = 0
        
        while True:
            # On cherche la signature commune des entités
            off = raw.find(SIG_COMMON, curr)
            if off == -1: break
            
            # Adresse potentielle de l'entité (calée sur l'offset 16 de la signature)
            ent_addr = start_addr + off - 8 
            
            if ent_addr != my_addr:
                # Lecture des coordonnées pour vérification
                c_buf = (ctypes.c_char * 24)()
                k32.ReadProcessMemory(h, ctypes.c_void_p(ent_addr), c_buf, 24, None)
                try:
                    tx, ty, tz = struct.unpack('<ddd', c_buf)
                    # Filtre : Si c'est à une distance raisonnable et cohérent
                    if 0 < ty < 255 and -30000000 < tx < 30000000:
                        print(f"[+] ENTITÉ TROUVÉE : {hex(ent_addr)} | Pos: {tx:.1f}, {ty:.1f}, {tz:.1f}")
                        found_count += 1
                except: pass
            
            curr = off + 1
        
        print(f"\n[*] Scan terminé. {found_count} entités identifiées.")
    else:
        print("[!] Impossible de lire le voisinage. Adresse protégée ou déplacée.")

spider_scan()
