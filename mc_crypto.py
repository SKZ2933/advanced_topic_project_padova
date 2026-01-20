"""
CHIFFREMENT MINECRAFT
======================
Gère le chiffrement RSA et AES pour la connexion aux serveurs online-mode.

- RSA: Chiffrement du shared secret avec la clé publique du serveur
- AES-128-CFB8: Chiffrement de tous les paquets après Encryption Response
- Server Hash: Calcul du hash pour la vérification session Mojang
"""

import os
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_shared_secret():
    """
    Génère un shared secret aléatoire de 16 bytes.
    Ce secret sera chiffré avec RSA et envoyé au serveur.
    """
    return os.urandom(16)


def encrypt_with_public_key(public_key_der, data):
    """
    Chiffre des données avec une clé publique RSA (PKCS1v15).
    
    Args:
        public_key_der: Clé publique au format DER (bytes)
        data: Données à chiffrer (bytes)
        
    Returns:
        bytes: Données chiffrées
    """
    public_key = serialization.load_der_public_key(public_key_der, default_backend())
    encrypted = public_key.encrypt(data, padding.PKCS1v15())
    return encrypted


def compute_server_hash(server_id, shared_secret, public_key_der):
    """
    Calcule le hash du serveur pour l'authentification Mojang.
    
    Le hash est calculé comme:
        SHA1(server_id + shared_secret + public_key)
    
    Note: Minecraft utilise un format spécial pour le hash:
    - Le digest SHA1 est interprété comme un entier signé big-endian
    - Si négatif, on prend le complément à deux et on préfixe avec '-'
    - Pas de padding avec des zéros
    
    Args:
        server_id: ID du serveur (string, souvent vide "")
        shared_secret: Secret partagé de 16 bytes
        public_key_der: Clé publique au format DER
        
    Returns:
        str: Hash hexadécimal (peut commencer par '-' si négatif)
    """
    sha1 = hashlib.sha1()
    sha1.update(server_id.encode('ascii'))
    sha1.update(shared_secret)
    sha1.update(public_key_der)
    
    digest = sha1.digest()
    
    # Vérifier si le nombre est négatif (bit de signe = 1)
    negative = digest[0] & 0x80
    
    if negative:
        # Complément à deux pour obtenir la valeur absolue
        # Inverser tous les bits et ajouter 1
        inverted = bytes(~b & 0xff for b in digest)
        number = int.from_bytes(inverted, byteorder='big') + 1
        return '-' + format(number, 'x')
    else:
        # Nombre positif - juste convertir en hex sans zéros de padding
        number = int.from_bytes(digest, byteorder='big')
        return format(number, 'x')


class AESCipher:
    """
    Chiffrement/déchiffrement AES-128-CFB8 pour les paquets Minecraft.
    
    Après le handshake de chiffrement, tous les paquets sont chiffrés
    avec AES en mode CFB8 (Cipher Feedback 8-bit).
    
    Note importante: Le chiffrement et le déchiffrement utilisent des
    états séparés qui doivent être maintenus tout au long de la connexion.
    """
    
    def __init__(self, shared_secret):
        """
        Initialise le cipher AES avec le shared secret.
        
        Args:
            shared_secret: 16 bytes utilisés comme clé ET IV initial
        """
        self.key = shared_secret
        
        # Créer des ciphers séparés pour encrypt/decrypt
        # (ils maintiennent des états indépendants)
        self._encryptor = Cipher(
            algorithms.AES(self.key),
            modes.CFB8(self.key),  # IV = clé pour Minecraft
            backend=default_backend()
        ).encryptor()
        
        self._decryptor = Cipher(
            algorithms.AES(self.key),
            modes.CFB8(self.key),
            backend=default_backend()
        ).decryptor()
    
    def encrypt(self, data):
        """
        Chiffre des données.
        
        Args:
            data: bytes à chiffrer
            
        Returns:
            bytes: Données chiffrées
        """
        return self._encryptor.update(data)
    
    def decrypt(self, data):
        """
        Déchiffre des données.
        
        Args:
            data: bytes chiffrés
            
        Returns:
            bytes: Données déchiffrées
        """
        return self._decryptor.update(data)


class EncryptedSocketWrapper:
    """
    Wrapper pour un socket qui chiffre/déchiffre automatiquement les données.
    
    Usage:
        encrypted_socket = EncryptedSocketWrapper(socket, shared_secret)
        encrypted_socket.send(data)  # Chiffre automatiquement
        data = encrypted_socket.recv(4096)  # Déchiffre automatiquement
    """
    
    def __init__(self, socket, shared_secret):
        """
        Args:
            socket: Socket TCP standard
            shared_secret: 16 bytes pour AES
        """
        self.socket = socket
        self.cipher = AESCipher(shared_secret)
    
    def send(self, data):
        """Chiffre et envoie les données"""
        encrypted = self.cipher.encrypt(data)
        return self.socket.send(encrypted)
    
    def sendall(self, data):
        """Chiffre et envoie toutes les données"""
        encrypted = self.cipher.encrypt(data)
        return self.socket.sendall(encrypted)
    
    def recv(self, bufsize):
        """Reçoit et déchiffre les données"""
        encrypted = self.socket.recv(bufsize)
        if not encrypted:
            return b''
        return self.cipher.decrypt(encrypted)
    
    def close(self):
        """Ferme le socket"""
        self.socket.close()
    
    def settimeout(self, timeout):
        """Définit le timeout"""
        self.socket.settimeout(timeout)
    
    def fileno(self):
        """Retourne le file descriptor"""
        return self.socket.fileno()


# ============================================================
# TEST
# ============================================================

def test_crypto():
    """Test des fonctions de chiffrement"""
    print("=== Test Chiffrement ===\n")
    
    # Test shared secret
    secret = generate_shared_secret()
    print(f"Shared Secret (16 bytes): {secret.hex()}")
    
    # Test AES
    cipher = AESCipher(secret)
    
    original = b"Hello Minecraft!"
    encrypted = cipher.encrypt(original)
    
    # Nouveau cipher pour déchiffrer (simule le serveur)
    cipher2 = AESCipher(secret)
    decrypted = cipher2.decrypt(encrypted)
    
    print(f"Original:  {original}")
    print(f"Encrypted: {encrypted.hex()}")
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == original, "Échec du chiffrement/déchiffrement!"
    print("\n[OK] Tests réussis!")


if __name__ == "__main__":
    test_crypto()
