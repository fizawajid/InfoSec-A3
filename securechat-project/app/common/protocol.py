"""
Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.
"""
from pydantic import BaseModel
from typing import Optional
from .utils import b64d  # For deserializing in future use

class Hello(BaseModel):
    type: str = "hello"
    client_cert: str  # PEM base64
    nonce: str  # base64

class ServerHello(BaseModel):
    type: str = "server_hello"
    server_cert: str  # PEM base64
    nonce: str  # base64

class Register(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(SHA256(salt||pwd)) - but we'll handle hashing in DB
    salt: str  # base64

class Login(BaseModel):
    type: str = "login"
    email: str
    pwd: str  # base64(SHA256(salt||pwd))
    nonce: str  # base64

class DHClient(BaseModel):
    type: str = "dh_client"
    g: int
    p: int
    A: int  # g^a mod p

class DHServer(BaseModel):
    type: str = "dh_server"
    B: int  # g^b mod p

class Message(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int  # unix ms
    ct: str  # base64 ciphertext
    sig: str  # base64(RSA-SIGN(SHA256(seqno||ts||ct)))

class Receipt(BaseModel):
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64(RSA-SIGN(transcript_sha256))
