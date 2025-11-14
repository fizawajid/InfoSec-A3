"""
AES-128 CBC encryption/decryption with PKCS7 padding
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from ..common.utils import b64e, b64d
import os

def encrypt_to_b64(key: bytes, plaintext: str) -> str:
    """Encrypt plaintext with AES-128 CBC and return base64 string."""
    # Generate random IV
    iv = os.urandom(16)
    
    # Pad the plaintext
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV + ciphertext as base64
    return b64e(iv + ciphertext)

def decrypt_from_b64(key: bytes, encrypted_b64: str) -> str:
    """Decrypt base64 encrypted data with AES-128 CBC."""
    # Decode from base64
    encrypted_data = b64d(encrypted_b64)
    
    # Extract IV and ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()
