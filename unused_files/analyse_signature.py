def find_stable_signature(dump1, txt1, dump2, txt2):
    def get_sigs(dump_path, txt_path):
        sigs = {}
        with open(dump_path, "rb") as d, open(txt_path, "r") as t:
            data = d.read()
            for line in t:
                addr = int(line.strip(), 16)
                # On prend les 16 octets juste AVANT les coordonnées X,Y,Z
                # C'est la "carte d'identité" de l'objet Java
                signature = data[addr-16:addr].hex()
                sigs[signature] = addr
        return sigs

    print("[*] Analyse des signatures...")
    sigs1 = get_sigs(dump1, txt1)
    sigs2 = get_sigs(dump2, txt2)

    # On cherche les signatures communes aux deux dumps
    communes = set(sigs1.keys()) & set(sigs2.keys())

    if not communes:
        print("[!] Aucune signature commune trouvée. Essayons avec une signature plus courte (8 octets)...")
        # (Optionnel : réduire la taille de la signature si 16 est trop strict)
    else:
        print(f"\n[!!!] {len(communes)} SIGNATURE(S) STABLE(S) TROUVÉE(S) !")
        for s in communes:
            print(f"Signature : {s}")
            print(f"  -> Présente au Dump 1 à : {hex(sigs1[s])}")
            print(f"  -> Présente au Dump 2 à : {hex(sigs2[s])}")

# UTILISATION :
find_stable_signature("dump1.bin", "candidats1.txt", "dump2.bin", "candidats2.txt")