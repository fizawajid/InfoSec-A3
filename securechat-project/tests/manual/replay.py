import os, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, ROOT)

from app.storage.transcript import Transcript
from app.common.utils import now_ms

def run():
    print("\n=== REPLAY TEST ===")

    t = Transcript("tests/manual/replay_transcript.csv", "dummyfp")

    # first message
    t.append(1, now_ms(), "aaa", "sig1")
    print("Sent seqno=1: OK")

    # replay same message
    print("Replay seqno=1 → EXPECT REPLAY")
    if 1 <= t.seqno:
        print("REPLAY")

    # new correct message
    t.append(2, now_ms(), "bbb", "sig2")
    print("Sent seqno=2: OK")

if __name__ == "__main__":
    run()
