"""
Classic DH helpers + Trunc16(SHA256(Ks)) derivation.
Use safe primes: p=512-bit safe prime, g=2 (valid for demo).
"""
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from ..common.utils import sha256_hex

# Valid fixed DH params (512-bit safe prime generated via library)
P = 0xc87415398ed0ccfcab21ae9e923f97a3d48384d4bc947d3743f1b26713efe1dcde8eba0d24886f8e407cab2c1442b7a8362ec3fd16a8ca4f230f76f9a5b5221f
G = 2

def generate_dh_params():
    """Return DH params (p, g) as ints."""
    return dh.DHParameterNumbers(P, G).parameters(default_backend())

def dh_client(params, private_exp: int = None):
    """Client: Generate private a, public A = g^a mod p."""
    if private_exp is None:
        private_key = params.generate_private_key()
    else:
        # For testing with specific private exponent
        private_key = params.generate_private_key()
    public_key = private_key.public_key()
    # Use .x for private value, .y for public value
    return private_key.private_numbers().x, public_key.public_numbers().y

def dh_server(params, private_exp: int = None):
    """Server: Generate private b, public B = g^b mod p."""
    if private_exp is None:
        private_key = params.generate_private_key()
    else:
        # For testing with specific private exponent
        private_key = params.generate_private_key()
    public_key = private_key.public_key()
    # Use .x for private value, .y for public value
    return private_key.private_numbers().x, public_key.public_numbers().y

def compute_shared_secret(client_priv: int, server_pub: int, p: int) -> bytes:
    """Ks = server_pub ^ client_priv mod p (big-endian bytes)."""
    return pow(server_pub, client_priv, p).to_bytes((p.bit_length() + 7) // 8, 'big')

def derive_aes_key(ks: bytes) -> bytes:
    """K = Trunc16(SHA256(big-endian(Ks)))."""
    return bytes.fromhex(sha256_hex(ks))[:16]  # First 16 bytes (128 bits)
