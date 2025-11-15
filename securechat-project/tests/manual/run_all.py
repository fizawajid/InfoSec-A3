import os
import json
import base64
import glob
import csv
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

from session_tools import generate_receipt
from nonrepudiation import verify_receipt

# ----------------------------------------------------
# Helper: find most recent transcript file
# ----------------------------------------------------
def find_latest(pattern):
    files = glob.glob(pattern)
    if not files:
        print(f"[ERROR] No files matching: {pattern}")
        return None
    latest = max(files, key=os.path.getctime)
    print(f"[✓] Found latest: {latest}")
    return latest

# ----------------------------------------------------
# Read transcript CSV
# ----------------------------------------------------
def read_transcript(path: Path):
    messages = []
    try:
        with open(path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                messages.append({
                    "timestamp": row.get("timestamp", ""),
                    "sender": row.get("sender", ""),
                    "message": row.get("message", ""),
                    "signature": row.get("signature", "")
                })
    except Exception as e:
        print(f"[ERROR] Failed reading transcript {path}: {e}")
    return messages

# ----------------------------------------------------
# Create session_receipt.json
# ----------------------------------------------------
def create_session_receipt():
    print("\n=== Creating session receipt... ===")

    # 1. Load latest transcript CSV
    try:
        transcript_files = list(Path(".").glob("client_transcript_*.csv"))
        if not transcript_files:
            print("[ERROR] No transcript CSV file found!")
            return False

        latest = max(transcript_files, key=lambda f: f.stat().st_mtime)
        msgs = read_transcript(latest)
    except Exception as e:
        print(f"[ERROR] Could not read transcript: {e}")
        return False

    # 2. Load public key from certificate
    try:
        with open("certs/client_cert.pem", "rb") as f:
            cert = load_pem_x509_certificate(f.read())
            pubkey_pem = cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
    except Exception as e:
        print(f"[ERROR] Failed to load client certificate: {e}")
        return False

    # 3. Build receipt (without signature)
    receipt_data = {
        "messages": msgs,
        "public_key": pubkey_pem,
        "client_signature": None
    }

    # 4. Canonical JSON for signing
    plaintext = json.dumps(
        {"messages": msgs, "public_key": pubkey_pem},
        sort_keys=True
    ).encode()

    # 5. Sign hash using private key
    try:
        with open("certs/client_private.key", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = private_key.sign(
            plaintext,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        receipt_data["client_signature"] = base64.b64encode(signature).decode()

    except Exception as e:
        print(f"[ERROR] Error during signature creation: {e}")
        return False

    # 6. Write receipt
    out_path = "tests/manual/session_receipt.json"
    try:
        with open(out_path, "w") as f:
            json.dump(receipt_data, f, indent=4)
        print(f"[✓] session_receipt.json created at {out_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to write receipt: {e}")
        return False


# ----------------------------------------------------
# Test: invalid certificate
# ----------------------------------------------------
def test_invalid_cert():
    print("\n=== Running invalid certificate test ===")
    try:
        load_pem_x509_certificate(b"INVALID DATA")
        print("[ERROR] Expected failure but certificate loaded!")
    except Exception:
        print("[✓] Invalid certificate correctly rejected.")

# ----------------------------------------------------
# Test: tampered signature
# ----------------------------------------------------
def test_tampered_signature():
    print("\n=== Running tampered signature test ===")
    try:
        path = "tests/manual/session_receipt.json"
        with open(path, "r") as f:
            data = json.load(f)

        data["client_signature"] = base64.b64encode(b"fakefakefake123").decode()

        with open("tests/manual/tampered.json", "w") as f:
            json.dump(data, f, indent=4)

        print("[✓] Tampered signature file created.")
    except Exception as e:
        print(f"[ERROR] {e}")

# ----------------------------------------------------
# Test: replay attack
# ----------------------------------------------------
def test_replay():
    print("\n=== Running replay attack test ===")
    source = "tests/manual/session_receipt.json"
    dest = "tests/manual/replay_copy.json"
    try:
        import shutil
        shutil.copy(source, dest)
        print("[✓] Replay copy created.")
    except Exception as e:
        print(f"[ERROR] {e}")

# ----------------------------------------------------
# Test: non-repudiation verification
# ----------------------------------------------------
def test_nonrepudiation():
    print("\n=== Running non-repudiation verification ===")
    path = "tests/manual/session_receipt.json"
    try:
        ok = verify_receipt(path)
        if ok:
            print("[✓] Non-repudiation verification successful.")
        else:
            print("[ERROR] Non-repudiation verification FAILED.")
    except Exception as e:
        print(f"[ERROR] {e}")

# ----------------------------------------------------
# MAIN
# ----------------------------------------------------
if __name__ == "__main__":
    print("\n==============================")
    print("  Running all security tests")
    print("==============================\n")

    if create_session_receipt():
        test_invalid_cert()
        test_tampered_signature()
        test_replay()
        test_nonrepudiation()

    print("\n=== ALL TESTS COMPLETED ===\n")
