"""
AES-128(ECB)+PKCS#7 helpers (use library).
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from .utils import b64e, b64d

def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 pad to block_size."""
    padder = padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def unpad_pkcs7(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    unpadder = padding.PKCS7(16).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-128 ECB encrypt with PKCS#7 pad."""
    ptext = pad_pkcs7(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(ptext) + encryptor.finalize()

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-128 ECB decrypt and unpad."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ptext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_pkcs7(ptext)

def encrypt_to_b64(key: bytes, plaintext: str) -> str:
    """Encrypt str to base64 ct."""
    ct = aes_encrypt(key, plaintext.encode())
    return b64e(ct)

def decrypt_from_b64(key: bytes, ct_b64: str) -> str:
    """Decrypt base64 ct to str."""
    ct = b64d(ct_b64)
    return aes_decrypt(key, ct).decode()
