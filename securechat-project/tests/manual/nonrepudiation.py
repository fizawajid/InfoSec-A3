import json, base64, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE = os.path.dirname(os.path.abspath(__file__))
RECEIPT = os.path.join(BASE, "session_receipt.json")

def verify_signature(pub, message: bytes, sig: bytes):
    try:
        pub.verify(
            sig,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def verify_receipt(path=RECEIPT):
    if not os.path.exists(path):
        print("[ERROR] session_receipt.json not found.")
        return False

    with open(path, "r") as f:
        receipt = json.load(f)

    # Load public key
    pubkey = serialization.load_pem_public_key(
        receipt["public_key"].encode()
    )

    # Reconstruct original signed structure
    signed_part = json.dumps(
        {"messages": receipt["messages"], "public_key": receipt["public_key"]},
        sort_keys=True
    ).encode()

    # Decode signature
    try:
        sig = base64.b64decode(receipt["client_signature"])
    except Exception:
        print("[ERROR] Could not decode client signature")
        return False

    # Verify
    try:
        pubkey.verify(
            sig,
            signed_part,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("[✓] Session signature verified successfully!")
        return True
    except Exception:
        print("[FAIL] Client session signature invalid")
        return False


if __name__ == "__main__":
    verify_receipt()
