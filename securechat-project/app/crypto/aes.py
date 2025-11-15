"""
AES-128 ECB encryption/decryption with PKCS7 padding
Note: ECB mode is used per assignment spec ("block cipher only, no modes")
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from ..common.utils import b64e, b64d

def encrypt_to_b64(key: bytes, plaintext: str) -> str:
    """
    Encrypt plaintext with AES-128 ECB and return base64 string.
    
    Note: ECB mode doesn't use IV, so we don't prepend anything.
    The ciphertext length will be a multiple of 16 bytes due to PKCS#7 padding.
    """
    # Pad the plaintext to block size (128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    # Encrypt with AES-128 ECB (no IV needed)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return ciphertext as base64 (no IV prepended)
    return b64e(ciphertext)

def decrypt_from_b64(key: bytes, encrypted_b64: str) -> str:
    """
    Decrypt base64 encrypted data with AES-128 ECB.
    
    Note: ECB mode doesn't use IV, so we decrypt directly.
    """
    # Decode from base64
    ciphertext = b64d(encrypted_b64)
    
    # Decrypt with AES-128 ECB (no IV needed)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad using PKCS#7
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()
