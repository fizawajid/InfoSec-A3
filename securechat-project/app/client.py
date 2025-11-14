"""
Client skeleton — plain TCP; no TLS. See assignment spec.
"""
import socket
import json
import getpass
import os
from cryptography.hazmat.backends import default_backend
from .common.protocol import Hello, ServerHello, DHClient, DHServer, Message, Receipt
from .common.utils import now_ms, b64e, b64d
from .crypto.pki import load_ca_cert, validate_cert, get_cert_fingerprint, load_cert
from .crypto.dh import generate_dh_params, dh_client, compute_shared_secret, derive_aes_key
from .crypto.aes import encrypt_to_b64, decrypt_from_b64
from .crypto.sign import sign_to_b64, verify_from_b64
from .storage.transcript import Transcript

HOST = 'localhost'
PORT = 12345
CA_CERT_PATH = 'certs/ca_cert.pem'
CLIENT_CERT_PATH = 'certs/client_cert.pem'
CLIENT_KEY_PATH = 'certs/client_private.key'
SERVER_CERT_PATH = 'certs/server_cert.pem'

class SecureClient:
    def __init__(self, username: str):
        self.username = username
        self.params = generate_dh_params()
        self.transcript = None
        self.session_key = None
        self.server_fingerprint = None
        self.expected_seqno = 1
        self.conn = None

    def connect(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((HOST, PORT))

    def send_json(self, data: dict):
        """Helper to send JSON with newline"""
        json_str = json.dumps(data)
        print(f"[CLIENT] Sending: {json_str[:100]}...")  # Debug
        self.conn.send((json_str + '\n').encode())

    def receive_json(self):
        """Helper to receive JSON line"""
        data = b''
        while b'\n' not in data:
            chunk = self.conn.recv(4096)
            if not chunk:
                return None
            data += chunk
        line = data.decode().split('\n')[0]  # Take first line only
        print(f"[CLIENT] Received: {line[:100]}...")  # Debug
        return json.loads(line)

    def run(self, mode: str = "login", email: str = None, password: str = None):
        self.connect()
        print("[CLIENT] Connected to server")

        # Phase 1: Hello
        # Read client certificate and encode as base64
        with open(CLIENT_CERT_PATH, 'rb') as f:
            client_pem_bytes = f.read()
        client_cert_b64 = b64e(client_pem_bytes)
        
        hello = Hello(
            client_cert=client_cert_b64, 
            nonce=b64e(os.urandom(16))
        )
        self.send_json(hello.model_dump())

        # Receive server hello
        server_hello_data = self.receive_json()
        if not server_hello_data:
            print("[CLIENT] No server hello received")
            return
            
        server_hello = ServerHello.model_validate(server_hello_data)
        
        # Validate server certificate
        ca_cert = load_ca_cert(CA_CERT_PATH)
        server_cert = load_cert(server_hello.server_cert)
        
        if not validate_cert(server_cert, ca_cert, "localhost"):
            print("[CLIENT] BAD SERVER CERT")
            return

        self.server_fingerprint = get_cert_fingerprint(server_cert)
        print(f"[CLIENT] Server certificate validated. Fingerprint: {self.server_fingerprint}")

        # Receive server's temp DH
        temp_dh_server_data = self.receive_json()
        if not temp_dh_server_data:
            print("[CLIENT] No temp DH from server")
            return
            
        temp_dh_server = DHServer.model_validate(temp_dh_server_data)
        
        # Generate client's temp DH and send
        # Generate client's temp DH and send
        print("[CLIENT] Generating temp DH keys...")
        temp_a, temp_A = dh_client(self.params)
        print(f"[CLIENT] Temp DH: private={temp_a}, public={temp_A}")
        temp_dh_client = DHClient(
            g=self.params.parameter_numbers().g, 
            p=self.params.parameter_numbers().p, 
            A=temp_A
        )
        self.send_json(temp_dh_client.model_dump())


        # Compute temp shared secret
        temp_Ks = compute_shared_secret(temp_a, temp_dh_server.B, self.params.parameter_numbers().p)
        temp_key = derive_aes_key(temp_Ks)
        print(f"[CLIENT] Temp key established: {temp_key.hex()}")

        # Send auth (register or login)
        if mode == "register":
            email = input("Email: ")
            username = self.username
            pwd = getpass.getpass("Password: ")
            auth_payload = {"type": "register", "email": email, "username": username, "password": pwd}
        else:
            email = email or input("Email: ")
            pwd = password or getpass.getpass("Password: ")
            auth_payload = {"type": "login", "email": email, "password": pwd}

        # Encrypt and send auth
        enc_auth = encrypt_to_b64(temp_key, json.dumps(auth_payload))
        self.send_json({"type": mode, "ct": enc_auth})

        # Receive auth response
        resp_data = self.receive_json()
        if not resp_data:
            print("[CLIENT] No auth response")
            return
            
        dec_resp = decrypt_from_b64(temp_key, resp_data['ct'])
        response = json.loads(dec_resp)
        
        if not response['success']:
            print(f"[CLIENT] Auth failed: {response.get('msg', 'Unknown error')}")
            return

        print("[CLIENT] Auth successful")

        # Phase 2: Session DH
        session_a, session_A = dh_client(self.params)
        dh_client_msg = DHClient(
            g=self.params.parameter_numbers().g, 
            p=self.params.parameter_numbers().p, 
            A=session_A
        )
        self.send_json(dh_client_msg.model_dump())

        dh_server_data = self.receive_json()
        if not dh_server_data:
            print("[CLIENT] No session DH from server")
            return
            
        dh_server_msg = DHServer.model_validate(dh_server_data)
        
        # Compute session key
        Ks = compute_shared_secret(session_a, dh_server_msg.B, self.params.parameter_numbers().p)
        self.session_key = derive_aes_key(Ks)
        print(f"[CLIENT] Session key established: {self.session_key.hex()}")

        # Initialize transcript
        self.transcript = Transcript(f"client_transcript_{now_ms()}.csv", self.server_fingerprint)

        print("[CLIENT] Starting chat loop...")
        # Phase 3: Chat loop
        while True:
            # Send message first
            user_input = input("[CLIENT] Send: ")
            if user_input.lower() == 'bye':
                break
                
            # Encrypt and sign message
            ct = encrypt_to_b64(self.session_key, user_input)
            ts = now_ms()
            seqno = self.expected_seqno
            hash_data = f"{seqno}|{ts}|{ct}".encode()
            sig = sign_to_b64(CLIENT_KEY_PATH, hash_data)
            
            client_msg = Message(seqno=seqno, ts=ts, ct=ct, sig=sig)
            self.send_json(client_msg.model_dump())
            
            # Add to transcript
            self.transcript.append(seqno, ts, ct, sig)
            self.expected_seqno += 1

            # Receive server response
            msg_data = self.receive_json()
            if not msg_data:
                break
                
            try:
                msg = Message.model_validate(msg_data)
            except Exception as e:
                print(f"[CLIENT] Invalid message format: {e}")
                continue

            # Verify sequence
            if msg.seqno != self.expected_seqno:
                print(f"[CLIENT] Sequence mismatch: expected {self.expected_seqno}, got {msg.seqno}")
                continue

            # Verify signature
            hash_data = f"{msg.seqno}|{msg.ts}|{msg.ct}".encode()
            if not verify_from_b64(SERVER_CERT_PATH, msg.sig, hash_data):
                print("[CLIENT] Signature verification failed")
                continue

            # Decrypt
            try:
                plaintext = decrypt_from_b64(self.session_key, msg.ct)
                print(f"[SERVER {msg.seqno}]: {plaintext}")
            except Exception as e:
                print(f"[CLIENT] Decryption failed: {e}")
                continue

            # Add to transcript
            self.transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig)
            self.expected_seqno += 1

            if plaintext.lower() == 'bye':
                break

        # Phase 4: Receive receipt
        try:
            receipt_data = self.receive_json()
            if receipt_data:
                receipt = Receipt.model_validate(receipt_data)
                print("[CLIENT] Server receipt received")
                print(f"  First seq: {receipt.first_seq}, Last seq: {receipt.last_seq}")
                print(f"  Transcript hash: {receipt.transcript_sha256}")
        except Exception as e:
            print(f"[CLIENT] No receipt received: {e}")

        # Generate own receipt
        if self.transcript:
            own_receipt = self.transcript.generate_receipt(CLIENT_KEY_PATH, 1)
            print("[CLIENT] Own receipt generated:")
            print(f"  First seq: {own_receipt['first_seq']}, Last seq: {own_receipt['last_seq']}")
            print(f"  Transcript hash: {own_receipt['transcript_sha256']}")

        self.conn.close()
        print("[CLIENT] Connection closed")

if __name__ == "__main__":
    mode = input("Register or Login? (r/l): ").lower()
    username = input("Username: ")
    client = SecureClient(username)
    if mode == 'r':
        client.run("register")
    else:
        client.run("login")
