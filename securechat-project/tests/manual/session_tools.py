import json, glob, os, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def latest_file(pattern):
    files = glob.glob(os.path.join(BASE, "..", pattern))
    if not files:
        return None
    return max(files, key=os.path.getctime)

def generate_receipt():
    client_csv = latest_file("client_transcript_*.csv")
    server_csv = latest_file("server_transcript_*.csv")

    if not client_csv or not server_csv:
        print("[ERROR] No transcripts found.")
        return None

    # Load messages from client transcript only (your project signs only outgoing messages)
    messages = []
    with open(client_csv, "r") as f:
        for line in f:
            if "," not in line:
                continue
            ts, msg, sig_b64 = line.strip().split(",", 2)
            messages.append({
                "time": ts,
                "data": msg,
                "signature": sig_b64
            })

    # Compute session digest (hash of all messages concatenated)
    digest = hashes.Hash(hashes.SHA256())
    for m in messages:
        digest.update(m["data"].encode())
    session_digest = digest.finalize()

    # Load public key from client_cert.pem
    cert_path = os.path.join(BASE, "..", "certs", "client_cert.pem")
    cert = open(cert_path, "rb").read()

    from cryptography import x509
    certificate = x509.load_pem_x509_certificate(cert)
    pubkey = certificate.public_key()

    receipt = {
        "messages": messages,
        "session_digest": base64.b64encode(session_digest).decode(),
        "public_key": certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()
    }

    # Sign final digest using client private key
    priv_path = os.path.join(BASE, "..", "certs", "client_private.key")
    private_key = serialization.load_pem_private_key(
        open(priv_path, "rb").read(),
        password=None
    )

    final_sig = private_key.sign(
        session_digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    receipt["final_signature"] = base64.b64encode(final_sig).decode()

    out_path = os.path.join(BASE, "session_receipt.json")
    with open(out_path, "w") as f:
        json.dump(receipt, f, indent=2)

    print(f"[✓] session_receipt.json created at {out_path}")
    return out_path
