import struct

def export_candidates(dump_file, target_x, target_y, target_z, output_txt, tolerance=0.1):
    print(f"[*] Scan de {dump_file}...")
    found = []
    
    with open(dump_file, "rb") as f:
        data = f.read()

    for i in range(0, len(data) - 24, 4):
        try:
            x, y, z = struct.unpack_from('<ddd', data, i)
            if (abs(x - target_x) < tolerance and 
                abs(y - target_y) < tolerance and 
                abs(z - target_z) < tolerance):
                found.append(hex(i))
        except:
            continue

    with open(output_txt, "w") as f:
        for addr in found:
            f.write(f"{addr}\n")
    
    print(f"[+] {len(found)} candidats exportés dans {output_txt}")


export_candidates("dump1.bin", -73.3, 64.0, -0.3, "candidats1.txt")
export_candidates("dump2.bin", -72.3, 65.0, -0.3, "candidats2.txt")