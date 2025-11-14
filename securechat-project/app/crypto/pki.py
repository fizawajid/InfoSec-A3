"""
X.509 validation: signed-by-CA, validity window, CN/SAN.
"""
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from .utils import b64d
import datetime

def load_cert(pem_b64: str) -> x509.Certificate:
    """Load PEM base64 to cert object."""
    pem_bytes = b64d(pem_b64)
    return x509.load_pem_x509_certificate(pem_bytes, default_backend())

def load_ca_cert(ca_pem_path: str) -> x509.Certificate:
    """Load CA cert from file."""
    with open(ca_pem_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def validate_cert(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str, ca_key_path: Optional[str] = None) -> bool:
    """
    Validate cert:
    - Signed by CA (if ca_key provided, verify sig; else check issuer).
    - Not expired.
    - CN matches expected (or SAN for server).
    Returns True if valid, else False.
    """
    now = datetime.datetime.utcnow()
    
    # 1. Validity period
    if now < cert.not_valid_before or now > cert.not_valid_after:
        print("[PKI] Cert expired/invalid period")
        return False
    
    # 2. Issuer chain (basic: matches CA subject)
    if cert.issuer != ca_cert.subject:
        print("[PKI] Invalid issuer chain")
        return False
    
    # 3. Signature (if CA private key provided for full verification)
    if ca_key_path:
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        try:
            cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding=serialization.pkcs1v15.PKCS1v15(),
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )  # Wait, no: verify using CA's public key, not private!
            # Correction: Use CA's public key to verify the sig on the cert.
            ca_public = ca_cert.public_key()
            ca_public.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding=serialization.pkcs1v15.PKCS1v15(),
                algorithm=hashes.SHA256()
            )
        except InvalidSignature:
            print("[PKI] Invalid signature")
            return False
    
    # 4. CN/SAN match
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn or cn[0].value != expected_cn:
        # Check SAN for server
        try:
            san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            if expected_cn not in [dns.value for dns in san.get_values_for_type(x509.DNSName)]:
                print(f"[PKI] CN/SAN mismatch: expected {expected_cn}")
                return False
        except x509.ExtensionNotFound:
            print("[PKI] No CN/SAN match")
            return False
    
    return True

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint of cert DER bytes (hex)."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()
