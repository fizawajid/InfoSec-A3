"""
Append-only transcript + TranscriptHash helpers.
"""
import csv
from typing import List
from ..common.utils import sha256_hex, now_ms

class Transcript:
    def __init__(self, filename: str, peer_cert_fingerprint: str):
        self.filename = filename
        self.peer_fingerprint = peer_cert_fingerprint
        self.lines: List[str] = []
        self.seqno = 0
        self.load_existing()  # For append-only

    def load_existing(self):
        """Load existing lines if file exists."""
        try:
            with open(self.filename, 'r') as f:
                reader = csv.reader(f)
                self.lines = [row[0] for row in reader]  # Assume single col
                if self.lines:
                    self.seqno = int(self.lines[-1].split('|')[0])  # Last seqno
        except FileNotFoundError:
            pass

    def append(self, seqno: int, ts: int, ct: str, sig: str):
        """Append: seqno | ts | ct | sig | peer-fp"""
        line = f"{seqno}|{ts}|{ct}|{sig}|{self.peer_fingerprint}"
        self.lines.append(line)
        self.seqno = seqno
        with open(self.filename, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([line])

    def compute_transcript_hash(self) -> str:
        """SHA256(concat all lines)."""
        concat = ''.join(self.lines).encode()
        return sha256_hex(concat)

    def generate_receipt(self, private_key_path: str, first_seq: int) -> dict:
        """Generate signed receipt."""
        from ..crypto.sign import sign_to_b64, load_private_key
        thash = self.compute_transcript_hash()
        sig_b64 = sign_to_b64(private_key_path, thash.encode())
        return {
            "type": "receipt",
            "peer": "client",  # Or "server" based on context
            "first_seq": first_seq,
            "last_seq": self.seqno,
            "transcript_sha256": thash,
            "sig": sig_b64
        }
