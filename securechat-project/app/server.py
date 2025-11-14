"""
Server skeleton — plain TCP; no TLS. See assignment spec.
"""
import socket
import json
from cryptography.hazmat.backends import default_backend
from .common.protocol import Hello, ServerHello, Register, Login, DHClient, DHServer, Message, Receipt
from .common.utils import now_ms, b64e, b64d, sha256_hex
from .storage.db import Database
from .crypto.pki import load_ca_cert, validate_cert, get_cert_fingerprint, load_cert
from .crypto.dh import generate_dh_params, dh_server, compute_shared_secret, derive_aes_key
from .crypto.aes import encrypt_to_b64, decrypt_from_b64
from .crypto.sign import verify_from_b64, sign_to_b64
from .storage.transcript import Transcript
import os

HOST = 'localhost'
PORT = 12345
CA_CERT_PATH = 'certs/ca_cert.pem'
SERVER_CERT_PATH = 'certs/server_cert.pem'
SERVER_KEY_PATH = 'certs/server_private.key'

class SecureServer:
    def __init__(self):
        self.params = generate_dh_params()
        self.db = Database()
        self.db.connect()
        self.transcript = None
        self.session_key = None
        self.client_fingerprint = None
        self.expected_seqno = 0

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            print(f"[SERVER] Listening on {HOST}:{PORT}")
            while True:
                conn, addr = s.accept()
                print(f"[SERVER] Client {addr} connected")
                self.handle_client(conn)

    def send_json(self, conn, data: dict):
        """Helper to send JSON with newline"""
        json_str = json.dumps(data)
        print(f"[SERVER] Sending: {json_str[:100]}...")  # Debug
        conn.send((json_str + '\n').encode())

    def receive_json(self, conn):
        """Helper to receive JSON line"""
        data = b''
        while b'\n' not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            data += chunk
        line = data.decode().split('\n')[0]  # Take first line only
        print(f"[SERVER] Received: {line[:100]}...")  # Debug
        return json.loads(line)

    def handle_client(self, conn):
        try:
            # Phase 1: Hello exchange
            hello_data = self.receive_json(conn)
            if not hello_data:
                print("[SERVER] No hello received")
                return
                
            hello = Hello.model_validate(hello_data)
            client_cert_b64 = hello.client_cert

            # Load and validate client cert
            ca_cert = load_ca_cert(CA_CERT_PATH)
            client_cert = load_cert(client_cert_b64)
            
            # For hello phase, we don't have username yet, so skip CN validation
            if not validate_cert(client_cert, ca_cert, ""):
                self.send_json(conn, {"error": "BAD CERT"})
                return

            self.client_fingerprint = get_cert_fingerprint(client_cert)
            print(f"[SERVER] Client certificate validated. Fingerprint: {self.client_fingerprint}")

            # Send server hello (base64 encoded)
            with open(SERVER_CERT_PATH, 'rb') as f:
                server_pem_bytes = f.read()
            server_cert_b64 = b64e(server_pem_bytes)
            
            server_hello = ServerHello(
                server_cert=server_cert_b64,
                nonce=b64e(os.urandom(16))
            )
            self.send_json(conn, server_hello.model_dump())


            # Temp DH for auth
            # Temp DH for auth
            print("[SERVER] Generating temp DH keys...")
            temp_b, temp_B = dh_server(self.params)
            print(f"[SERVER] Temp DH: private={temp_b}, public={temp_B}")
            temp_dh_server_msg = DHServer(B=temp_B)
            self.send_json(conn, temp_dh_server_msg.model_dump())

            # Wait for client's DH parameters for temp key
            temp_dh_data = self.receive_json(conn)
            if not temp_dh_data:
                print("[SERVER] No temp DH from client")
                return
                
            temp_dh = DHClient.model_validate(temp_dh_data)
            
            # Compute temp shared secret
            temp_Ks = compute_shared_secret(temp_b, temp_dh.A, self.params.parameter_numbers().p)
            temp_key = derive_aes_key(temp_Ks)
            print(f"[SERVER] Temp key established: {temp_key.hex()}")

            # Receive encrypted auth message
            auth_data = self.receive_json(conn)
            if not auth_data:
                print("[SERVER] No auth data received")
                return
                
            if 'ct' not in auth_data:
                self.send_json(conn, {"error": "No ciphertext"})
                return

            try:
                decrypted = decrypt_from_b64(temp_key, auth_data['ct'])
                auth_msg = json.loads(decrypted)
                print(f"[SERVER] Decrypted auth: {auth_msg}")
            except Exception as e:
                print(f"[SERVER] Decryption failed: {e}")
                self.send_json(conn, {"error": f"Decryption failed: {e}"})
                return

            # Handle registration or login
            if auth_msg['type'] == 'register':
                email = auth_msg['email']
                username = auth_msg['username']
                password = auth_msg['password']
                
                success, msg = self.db.register_user(email, username, password)
                response = {"success": success, "msg": msg}
                print(f"[SERVER] Registration: {success}, {msg}")
                
            else:  # login
                email = auth_msg['email']
                password = auth_msg['password']
                
                success, username = self.db.authenticate_user(email, password)
                response = {"success": success, "username": username}
                print(f"[SERVER] Login: {success}, {username}")

            # Send encrypted response
            enc_response = encrypt_to_b64(temp_key, json.dumps(response))
            self.send_json(conn, {"type": "auth_response", "ct": enc_response})

            if not success:
                print("[SERVER] Auth failed, closing connection")
                return

            print(f"[SERVER] Auth successful for {username}")

            # Phase 2: Session DH - Wait for client's session DH
            session_dh_data = self.receive_json(conn)
            if not session_dh_data:
                print("[SERVER] No session DH from client")
                return
                
            session_dh = DHClient.model_validate(session_dh_data)
            
            # Generate server's session DH
            session_b, session_B = dh_server(self.params)
            session_dh_server_msg = DHServer(B=session_B)
            self.send_json(conn, session_dh_server_msg.model_dump())

            # Compute session key
            session_Ks = compute_shared_secret(session_b, session_dh.A, self.params.parameter_numbers().p)
            self.session_key = derive_aes_key(session_Ks)
            print(f"[SERVER] Session key established: {self.session_key.hex()}")

            # Initialize transcript
            self.transcript = Transcript(f"server_transcript_{now_ms()}.csv", self.client_fingerprint)
            self.expected_seqno = 1

            print("[SERVER] Starting chat loop...")
            # Phase 3: Chat loop
            while True:
                msg_data = self.receive_json(conn)
                if not msg_data:
                    print("[SERVER] No message data")
                    break
                    
                try:
                    msg = Message.model_validate(msg_data)
                except Exception as e:
                    print(f"[SERVER] Invalid message format: {e}")
                    continue

                # Verify sequence number
                if msg.seqno != self.expected_seqno:
                    print(f"[SERVER] Sequence mismatch: expected {self.expected_seqno}, got {msg.seqno}")
                    self.send_json(conn, {"error": "REPLAY"})
                    continue

                # Verify signature
                hash_data = f"{msg.seqno}|{msg.ts}|{msg.ct}".encode()
                if not verify_from_b64(CLIENT_CERT_PATH, msg.sig, hash_data):
                    print("[SERVER] Signature verification failed")
                    self.send_json(conn, {"error": "SIG FAIL"})
                    continue

                # Decrypt message
                try:
                    plaintext = decrypt_from_b64(self.session_key, msg.ct)
                    print(f"[CLIENT {msg.seqno}]: {plaintext}")
                except Exception as e:
                    print(f"[SERVER] Decryption failed: {e}")
                    continue

                # Add to transcript
                self.transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig)
                self.expected_seqno += 1

                # Check for exit condition
                if plaintext.lower() == 'bye':
                    break

                # Get server response
                response_plain = input("[SERVER] Send: ")
                if response_plain.lower() == 'bye':
                    break
                    
                # Encrypt and sign response
                response_ct = encrypt_to_b64(self.session_key, response_plain)
                server_ts = now_ms()
                server_seqno = self.expected_seqno
                server_hash_data = f"{server_seqno}|{server_ts}|{response_ct}".encode()
                server_sig = sign_to_b64(SERVER_KEY_PATH, server_hash_data)
                
                response_msg = Message(
                    seqno=server_seqno, 
                    ts=server_ts, 
                    ct=response_ct, 
                    sig=server_sig
                )
                self.send_json(conn, response_msg.model_dump())

                # Add server's own message to transcript
                self.transcript.append(server_seqno, server_ts, response_ct, server_sig)
                self.expected_seqno += 1

            # Phase 4: Generate receipt
            if self.transcript:
                receipt = self.transcript.generate_receipt(SERVER_KEY_PATH, 1)
                self.send_json(conn, receipt)
                print("[SERVER] Receipt sent")

            print("[SERVER] Session ended")

        except Exception as e:
            print(f"[SERVER ERROR]: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()

if __name__ == "__main__":
    server = SecureServer()
    server.start()
