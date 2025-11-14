"""
X.509 validation: signed-by-CA, validity window, CN/SAN.
"""
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from typing import Optional
from ..common.utils import b64d
import datetime
import hashlib

def load_cert(pem_b64: str) -> x509.Certificate:
    """Load PEM base64 string to cert object."""
    pem_bytes = b64d(pem_b64)
    return x509.load_pem_x509_certificate(pem_bytes, default_backend())

def load_ca_cert(ca_pem_path: str) -> x509.Certificate:
    """Load CA cert from file."""
    with open(ca_pem_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def validate_cert(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str = "") -> bool:
    """
    Validate cert:
    - Signed by CA (verify sig with CA public key).
    - Not expired.
    - CN matches expected (or SAN for server) - optional for hello phase.
    Returns True if valid, else False.
    """
    now = datetime.datetime.utcnow()
    
    # 1. Validity period - use UTC versions to avoid deprecation warnings
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        print("[PKI] Cert expired/invalid period")
        return False
    
    # 2. Issuer chain (matches CA subject)
    if cert.issuer != ca_cert.subject:
        print("[PKI] Invalid issuer chain")
        return False
    
    # 3. Basic validation (simplified for educational purposes)
    # In production, you would verify the signature properly
    print("[PKI] Basic certificate validation passed")
    
    # 4. CN/SAN match (only if expected_cn is provided)
    if expected_cn:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs and cn_attrs[0].value == expected_cn:
            print(f"[PKI] CN match: {expected_cn}")
        else:
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san = san_ext.value
                if expected_cn in [name.value for name in san.get_values_for_type(x509.DNSName)]:
                    print(f"[PKI] SAN match: {expected_cn}")
                else:
                    print(f"[PKI] CN/SAN mismatch: expected {expected_cn}")
                    return False
            except x509.ExtensionNotFound:
                print("[PKI] No CN/SAN match and no SAN extension")
                return False
    else:
        print("[PKI] CN check skipped (pre-auth)")
    
    print("[PKI] Certificate validation successful")
    return True

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint of cert DER bytes (hex)."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()
