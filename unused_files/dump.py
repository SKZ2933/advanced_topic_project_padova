import ctypes
import os
from ctypes import wintypes

def dump_process_memory(proc_name, output_file):
    k32 = ctypes.windll.kernel32
    PROCESS_ALL_ACCESS = 0x1F0FFF
    
    # --- CONFIGURATION 64 BITS ---
    # On définit explicitement les types d'entrée/sortie pour éviter l'Overflow
    k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    # 1. Trouver le PID
    try:
        tasks = os.popen(f'tasklist /FI "IMAGENAME eq {proc_name}"').read()
        pid = int(tasks.splitlines()[3].split()[1])
        print(f"[*] Processus trouvé ! PID: {pid}")
    except Exception:
        print("[!] Erreur: Minecraft (javaw.exe) n'est pas lancé.")
        return
    
    handle = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        print("[!] Impossible d'ouvrir le processus. Lancez en ADMIN.")
        return
    
    # 2. Structure MBI pour 64 bits
    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("PartitionId", wintypes.WORD), # Spécifique x64
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]
    
    address = 0
    mbi = MBI()
    
    print("[*] Début du dump... Analyse de la RAM en cours.")
    
    with open(output_file, "wb") as f:
        while k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            # MEM_COMMIT = 0x1000 et PAGE_READWRITE = 0x04
            if mbi.State == 0x1000 and mbi.Protect == 0x04:
                size = mbi.RegionSize
                buf = (ctypes.c_char * size)()
                # On lit la mémoire par blocs
                if k32.ReadProcessMemory(handle, mbi.BaseAddress, buf, size, None):
                    f.write(buf.raw)
            
            # On passe à l'adresse suivante
            address = (mbi.BaseAddress or 0) + mbi.RegionSize
            
    print(f"[+] Terminé ! Fichier créé : {os.path.abspath(output_file)}")
    k32.CloseHandle(handle)

if __name__ == "__main__":
    dump_process_memory("javaw.exe", "minecraft_ram.bin")