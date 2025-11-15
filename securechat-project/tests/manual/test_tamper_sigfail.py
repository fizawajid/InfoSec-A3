"""
Test: Tamper Ciphertext → SIG_FAIL
"""

import os, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, ROOT)

from app.crypto.sign import verify_from_pem
from app.crypto.aes import encrypt_to_b64
from app.common.utils import sha256_hex, b64d, b64e
from app.crypto.sign import sign_to_b64

PRIVATE_KEY = "certs/server_private.key"
SERVER_CERT = "certs/server_cert.pem"

def flip_bit(b: bytes) -> bytes:
    arr = bytearray(b)
    arr[0] ^= 1        # flip lowest bit
    return bytes(arr)

def run():
    print("\n=== TAMPERING TEST (SIG_FAIL) ===")

    message = b"Attack at dawn"
    ciphertext_b64 = encrypt_to_b64(b"0000000000000000", message.decode())

    digest = sha256_hex(ciphertext_b64.encode()).encode()
    sig = sign_to_b64(PRIVATE_KEY, digest)

    print("\n[OK] Original signature verifies:")
    print(verify_from_pem(open(SERVER_CERT,"rb").read(), sig, digest))

    # Tamper CT → MUST FAIL
    tampered_ct = b64e(flip_bit(b64d(ciphertext_b64)))
    tampered_digest = sha256_hex(tampered_ct.encode()).encode()

    print("\n[TAMPER] Tampered signature verifies:")
    print("Expected: False → SIG_FAIL")
    print("Actual:", verify_from_pem(open(SERVER_CERT,"rb").read(), sig, tampered_digest))

    print("\n✓ Tampering test complete.")

if __name__ == "__main__":
    run()
