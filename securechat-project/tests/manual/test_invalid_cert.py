"""
Test: Invalid Certificate Detection → BAD_CERT
"""

import os, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, ROOT)

import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from app.crypto.pki import validate_cert, load_ca_cert



CA_CERT = "certs/ca_cert.pem"
SERVER_CERT = "certs/server_cert.pem"         # normal server cert
FORGED_CERT = "tests/manual/forged_cert.pem"  # fake

def load_pem(path):
    with open(path, "rb") as f:
        return f.read()

def run():
    print("\n=== INVALID CERTIFICATE TEST ===")

    ca = load_ca_cert(CA_CERT)

    print("\n[1] Valid server cert → EXPECT VALID")
    valid_cert = x509.load_pem_x509_certificate(load_pem(SERVER_CERT))
    print("Result:", "OK" if validate_cert(valid_cert, ca, "SecureChat Server") else "BAD_CERT")

    print("\n[2] Forged/self-signed cert → EXPECT BAD_CERT")
    forged = x509.load_pem_x509_certificate(load_pem(FORGED_CERT))
    print("Result:", "OK" if validate_cert(forged, ca, "SecureChat Server") else "BAD_CERT")

    print("\n✓ Invalid certificate test complete.")
    
if __name__ == "__main__":
    run()
