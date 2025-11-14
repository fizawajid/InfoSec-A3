"""
Classic DH helpers + Trunc16(SHA256(Ks)) derivation.
Use safe primes: p=23-bit, g=2 (or standard).
"""
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .utils import sha256_hex

# Standard DH params (small for demo; use larger in prod)
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B8F4798E542BE5D97
G = 2

def generate_dh_params():
    """Return DH params (p, g)."""
    return dh.DHParameterNumbers(P, G).parameters(default_backend())

def dh_client(params, private_exp: int = None):
    """Client: Generate private a, public A = g^a mod p."""
    if private_exp is None:
        private_key = params.generate_private_key()
    else:
        private_key = params.private_key(private_exp)
    public_key = private_key.public_key()
    return private_key.private_numbers().private_value, public_key.public_numbers().y

def dh_server(params, private_exp: int = None):
    """Server: Generate private b, public B = g^b mod p."""
    if private_exp is None:
        private_key = params.generate_private_key()
    else:
        private_key = params.private_key(private_exp)
    public_key = private_key.public_key()
    return private_key.private_numbers().private_value, public_key.public_numbers().y

def compute_shared_secret(client_priv: int, server_pub: int, p: int) -> bytes:
    """Ks = server_pub ^ client_priv mod p (big-endian bytes)."""
    return pow(server_pub, client_priv, p).to_bytes((p.bit_length() + 7) // 8, 'big')

def derive_aes_key(ks: bytes) -> bytes:
    """K = Trunc16(SHA256(big-endian(Ks)))."""
    ks_hex = sha256_hex(ks)
    return bytes.fromhex(ks_hex)[:16]  # First 16 bytes (128 bits)
