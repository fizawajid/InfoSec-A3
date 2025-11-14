"""
RSA PKCS#1 v1.5 SHA-256 sign/verify.
"""
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from ..common.utils import b64e, b64d

def load_private_key(pem_path: str) -> rsa.RSAPrivateKey:
    """Load PEM private key."""
    with open(pem_path, "rb") as f:
        return load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key_from_cert(pem_path: str) -> rsa.RSAPublicKey:
    """Load PEM public key from certificate file."""
    with open(pem_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert.public_key()

def load_public_key_from_pem(pem_data: bytes) -> rsa.RSAPublicKey:
    """Load public key from PEM bytes (from certificate)."""
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert.public_key()

def sign_rsa(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """RSA-SIGN(SHA256(data)) PKCS1v1.5."""
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_rsa(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """Verify RSA sig over data using SHA256."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False

def sign_to_b64(private_key_path: str, data: bytes) -> str:
    """Sign and base64."""
    key = load_private_key(private_key_path)
    sig = sign_rsa(key, data)
    return b64e(sig)

def verify_from_b64(cert_path: str, sig_b64: str, data: bytes) -> bool:
    """Verify base64 sig using certificate."""
    key = load_public_key_from_cert(cert_path)
    sig = b64d(sig_b64)
    return verify_rsa(key, sig, data)

def verify_from_pem(cert_pem: bytes, sig_b64: str, data: bytes) -> bool:
    """Verify base64 sig using PEM certificate bytes."""
    key = load_public_key_from_pem(cert_pem)
    sig = b64d(sig_b64)
    return verify_rsa(key, sig, data)
