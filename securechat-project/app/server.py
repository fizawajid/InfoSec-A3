# Modified server.py with signature verification fix and incoming-message print
# (Full updated file)

import socket
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509
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

def verify_sig_with_cert(cert: x509.Certificate, sig_b64: str, data: bytes) -> bool:
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    pub = cert.public_key()
    try:
        pub.verify(
            sig,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

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
        json_str = json.dumps(data)
        conn.send((json_str + '\n').encode())
    def receive_json(self, conn):
        data = b''
        while b'\n' not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            data += chunk
        line = data.decode().split('\n')[0]
        return json.loads(line)
    def handle_client(self, conn):
        try:
            hello_data = self.receive_json(conn)
            if not hello_data:
                return
            hello = Hello.model_validate(hello_data)
            client_cert_b64 = hello.client_cert
            ca_cert = load_ca_cert(CA_CERT_PATH)
            client_cert = load_cert(client_cert_b64)
            if not validate_cert(client_cert, ca_cert, ""):
                self.send_json(conn, {"error": "BAD CERT"})
                return
            self.client_fingerprint = get_cert_fingerprint(client_cert)
            with open(SERVER_CERT_PATH, 'rb') as f:
                server_pem_bytes = f.read()
            server_cert_b64 = b64e(server_pem_bytes)
            server_hello = ServerHello(server_cert=server_cert_b64, nonce=b64e(os.urandom(16)))
            self.send_json(conn, server_hello.model_dump())
            print("[SERVER] Generating temp DH keys...")
            temp_b, temp_B = dh_server(self.params)
            self.send_json(conn, DHServer(B=temp_B).model_dump())
            temp_dh_data = self.receive_json(conn)
            if not temp_dh_data:
                return
            temp_dh = DHClient.model_validate(temp_dh_data)
            temp_Ks = compute_shared_secret(temp_b, temp_dh.A, self.params.parameter_numbers().p)
            temp_key = derive_aes_key(temp_Ks)
            auth_data = self.receive_json(conn)
            if not auth_data or 'ct' not in auth_data:
                return
            decrypted = decrypt_from_b64(temp_key, auth_data['ct'])
            auth_msg = json.loads(decrypted)
            if auth_msg['type'] == 'register':
                email = auth_msg['email']
                username = auth_msg['username']
                password = auth_msg['password']
                success, msg = self.db.register_user(email, username, password)
                response = {"success": success, "msg": msg}
            else:
                email = auth_msg['email']
                password = auth_msg['password']
                success, username = self.db.authenticate_user(email, password)
                response = {"success": success, "username": username}
            enc_response = encrypt_to_b64(temp_key, json.dumps(response))
            self.send_json(conn, {"type": "auth_response", "ct": enc_response})
            if not success:
                return
            session_dh_data = self.receive_json(conn)
            if not session_dh_data:
                return
            session_dh = DHClient.model_validate(session_dh_data)
            session_b, session_B = dh_server(self.params)
            self.send_json(conn, DHServer(B=session_B).model_dump())
            session_Ks = compute_shared_secret(session_b, session_dh.A, self.params.parameter_numbers().p)
            self.session_key = derive_aes_key(session_Ks)
            self.transcript = Transcript(f"server_transcript_{now_ms()}.csv", self.client_fingerprint)
            self.expected_seqno = 1
            while True:
                msg_data = self.receive_json(conn)
                if not msg_data:
                    break
                msg = Message.model_validate(msg_data)
                if msg.seqno != self.expected_seqno:
                    self.send_json(conn, {"error": "REPLAY"})
                    continue
                hash_data = f"{msg.seqno}|{msg.ts}|{msg.ct}".encode()
                if not verify_sig_with_cert(client_cert, msg.sig, hash_data):
                    self.send_json(conn, {"error": "SIG FAIL"})
                    continue
                plaintext = decrypt_from_b64(self.session_key, msg.ct)

                # --- New: ensure plaintext is string and print it for server operator ---
                if isinstance(plaintext, bytes):
                    try:
                        plaintext = plaintext.decode('utf-8', errors='replace')
                    except Exception:
                        plaintext = str(plaintext)
                print(f"[SERVER] CLIENT {msg.seqno}: {plaintext}")  # show client's message

                self.transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig)
                self.expected_seqno += 1
                if plaintext.lower() == 'bye':
                    break
                response_plain = input("[SERVER] Send: ")
                if response_plain.lower() == 'bye':
                    break
                response_ct = encrypt_to_b64(self.session_key, response_plain)
                server_ts = now_ms()
                server_seqno = self.expected_seqno
                server_hash_data = f"{server_seqno}|{server_ts}|{response_ct}".encode()
                server_sig = sign_to_b64(SERVER_KEY_PATH, server_hash_data)
                response_msg = Message(seqno=server_seqno, ts=server_ts, ct=response_ct, sig=server_sig)
                self.send_json(conn, response_msg.model_dump())
                self.transcript.append(server_seqno, server_ts, response_ct, server_sig)
                self.expected_seqno += 1
            if self.transcript:
                receipt = self.transcript.generate_receipt(SERVER_KEY_PATH, 1)
                self.send_json(conn, receipt)
        except Exception as e:
            print(f"[SERVER ERROR]: {e}")
        finally:
            conn.close()
if __name__ == "__main__":
    server = SecureServer()
    server.start()
