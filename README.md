#  SecureChat — End-to-End Encrypted Messaging System  
*A secure communication project implementing TLS-style mutual authentication, Diffie–Hellman key exchange, AES encryption, integrity verification, replay protection, and non-repudiation.*


## 📌 1. Overview

SecureChat is a client–server encrypted messaging system designed for demonstrating secure communication protocols.  
It includes:

- CA-signed certificates  
- Mutual authentication  
- RSA-2048 signature verification  
- Diffie–Hellman key exchange  
- AES-256-CBC encryption  
- SHA-256 HMAC integrity checking  
- Replay-attack protection  
- Non-repudiation via signed session receipts  
- Manual security tests  
- Wireshark traffic analysis  

This project was developed as part of a computer security assignment.

#4. How to Run the Project
 Step 1 — Start the Server
python server.py
Expected output:
[SERVER] Listening on port 12345...
[SERVER] Waiting for client handshake...

 Step 2 — Start the Client
python client.py
Expected handshake output:
[CLIENT] Connected to server.
[CLIENT] Verifying server certificate...
[CLIENT] Running Diffie–Hellman key exchange...
[CLIENT] Secure session established.

Step 3 — Exchange Encrypted Messages
step 4. Manual Security Tests
Run all tests:
python tests/manual/run_all.py
=== Running invalid certificate test ===
[✓] Invalid certificate correctly rejected.

=== Running tampered signature test ===
[✓] Tampered signature detected.

=== Running replay attack test ===
[✓] Replay copy rejected.

=== Running non-repudiation verification ===
[✓] Client signature verified.

=== ALL TESTS COMPLETED ===


8. Security Features Implemented
RSA-2048 certificates
CA signature verification
Diffie–Hellman key exchange
AES-256-CBC encryption
SHA-256 integrity
Anti-replay protection
Timestamp checking
Sequence numbers
Signed session receipts
Non-repudiation using RSA signatures

9. github repository link
    ttps://github.com/fizawajid/InfoSec-A3
   


