"""
Minecraft Encryption Module
Handles RSA and AES-128-CFB8 encryption for online-mode server connections.
"""

import os
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# =============================================================================
# RSA ENCRYPTION
# =============================================================================

def generate_shared_secret():
    """Generate a random 16-byte shared secret for AES encryption."""
    return os.urandom(16)


def encrypt_with_public_key(public_key_der: bytes, data: bytes) -> bytes:
    """Encrypt data with server's RSA public key (PKCS1v15 padding)."""
    public_key = serialization.load_der_public_key(public_key_der, default_backend())
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("Expected RSA public key")
    return public_key.encrypt(data, padding.PKCS1v15())


# =============================================================================
# SERVER HASH (Mojang Session Authentication)
# =============================================================================

def compute_server_hash(server_id, shared_secret, public_key_der):
    """
    Compute the server hash for Mojang session validation.
    
    Minecraft uses a special format:
    - SHA1(server_id + shared_secret + public_key)
    - Interpreted as a signed big-endian integer
    - Negative values are prefixed with '-' (two's complement)
    """
    sha1 = hashlib.sha1()
    sha1.update(server_id.encode('ascii'))
    sha1.update(shared_secret)
    sha1.update(public_key_der)
    digest = sha1.digest()

    # Check if negative (high bit set)
    if digest[0] & 0x80:
        # Two's complement for negative numbers
        inverted = bytes(~b & 0xff for b in digest)
        number = int.from_bytes(inverted, 'big') + 1
        return '-' + format(number, 'x')
    else:
        number = int.from_bytes(digest, 'big')
        return format(number, 'x')


# =============================================================================
# AES CIPHER
# =============================================================================

class AESCipher:
    """
    AES-128-CFB8 cipher for Minecraft packet encryption.
    Uses the shared secret as both key and IV.
    """

    def __init__(self, shared_secret):
        self.key = shared_secret
        # Separate encryptor/decryptor maintain independent state
        self._encryptor = Cipher(
            algorithms.AES(self.key),
            modes.CFB8(self.key),
            default_backend()
        ).encryptor()
        self._decryptor = Cipher(
            algorithms.AES(self.key),
            modes.CFB8(self.key),
            default_backend()
        ).decryptor()

    def encrypt(self, data):
        """Encrypt data bytes."""
        return self._encryptor.update(data)

    def decrypt(self, data):
        """Decrypt data bytes."""
        return self._decryptor.update(data)


# =============================================================================
# ENCRYPTED SOCKET WRAPPER
# =============================================================================

class EncryptedSocketWrapper:
    """
    Wraps a socket to automatically encrypt/decrypt all traffic.
    Drop-in replacement for socket after encryption is enabled.
    """

    def __init__(self, socket, shared_secret):
        self.socket = socket
        self.cipher = AESCipher(shared_secret)

    def send(self, data):
        """Encrypt and send data."""
        return self.socket.send(self.cipher.encrypt(data))

    def sendall(self, data):
        """Encrypt and send all data."""
        return self.socket.sendall(self.cipher.encrypt(data))

    def recv(self, bufsize):
        """Receive and decrypt data."""
        encrypted = self.socket.recv(bufsize)
        if not encrypted:
            return b''
        return self.cipher.decrypt(encrypted)

    def close(self):
        self.socket.close()

    def settimeout(self, timeout):
        self.socket.settimeout(timeout)

    def fileno(self):
        return self.socket.fileno()
