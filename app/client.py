# client.py
import ssl
import socket
import json
import os
import hashlib
import struct
import threading
import time
import base64
from secrets import randbelow

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

# ----------------- CONFIG -----------------
HOST = '127.0.0.1'
PORT = 8443
CERT_DIR = 'certs'
CA_CERT = os.path.join(CERT_DIR, 'ca.cert.pem')
CLIENT_CERT = os.path.join(CERT_DIR, 'client1.cert.pem')
CLIENT_KEY = os.path.join(CERT_DIR, 'client1.key.pem')

TRANSCRIPT_FILE = 'client_transcript.log'
RECEIPT_FILE = 'client_receipt.json'
# ------------------------------------------

# Classical DH public parameters (both sides must use same)
p = 0xE95E4A5F737059DC60DF5991D45029409E60FC09
g = 2
INT_LEN = (p.bit_length() + 7) // 8

# ---------- framing ----------
def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError('Connection closed')
        data += chunk
    return data

def recv_message(sock):
    raw = recv_exact(sock, 4)
    (l,) = struct.unpack('!I', raw)
    return recv_exact(sock, l)

def send_message(sock, b):
    sock.sendall(struct.pack('!I', len(b)) + b)

# ---------- crypto ----------
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv, ct

def aes_decrypt(key, iv, ct):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def derive_session_key_from_Ks(Ks_int):
    ks_bytes = Ks_int.to_bytes((Ks_int.bit_length() + 7) // 8, 'big')
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_cert_pubkey_from_der(der_bytes):
    cert = x509.load_der_x509_certificate(der_bytes)
    return cert, cert.public_key()

def cert_fingerprint_hex(der_bytes):
    return hashlib.sha256(der_bytes).hexdigest()

# ---------- Chat session ----------
class ChatClient:
    def __init__(self, tls_sock, peer_cert_der, client_privkey):
        self.sock = tls_sock
        self.peer_cert_der = peer_cert_der
        self.peer_cert, self.peer_pubkey = load_cert_pubkey_from_der(peer_cert_der)
        self.peer_fp = cert_fingerprint_hex(peer_cert_der)
        self.privkey = client_privkey
        self.session_key = None
        self.our_seq = 0
        self.peer_last_seq = 0
        self.transcript_lines = []
        self.running = True

    def classical_dh_exchange(self):
        # server will send B first (per server implementation), then client sends A
        server_B_bytes = recv_message(self.sock)
        B = int.from_bytes(server_B_bytes, 'big')
        a = randbelow(p - 2) + 2
        A = pow(g, a, p)
        A_bytes = A.to_bytes(INT_LEN, 'big')
        send_message(self.sock, A_bytes)
        Ks = pow(B, a, p)
        self.session_key = derive_session_key_from_Ks(Ks)
        print('Session key established (hex):', self.session_key.hex())

    def sign_message_bytes(self, seqno, ts_ms, ct_bytes):
        seqb = int(seqno).to_bytes(8, 'big')
        tsb = int(ts_ms).to_bytes(8, 'big')
        msg = seqb + tsb + ct_bytes
        sig = self.privkey.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        return sig

    def verify_peer_signature(self, seqno, ts_ms, ct_bytes, sig_bytes):
        seqb = int(seqno).to_bytes(8, 'big')
        tsb = int(ts_ms).to_bytes(8, 'big')
        msg = seqb + tsb + ct_bytes
        try:
            self.peer_pubkey.verify(sig_bytes, msg, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False

    def append_transcript_line(self, seqno, ts_ms, ct_b64, sig_b64):
        line = f"{seqno}|{ts_ms}|{ct_b64}|{sig_b64}|{self.peer_fp}\n"
        with open(TRANSCRIPT_FILE, 'a') as f:
            f.write(line)
        self.transcript_lines.append(line.encode())

    def sender_loop(self):
        try:
            while self.running:
                plaintext = input('You> ')
                if plaintext.strip() == '':
                    continue
                if plaintext.strip() == '/exit':
                    self.running = False
                    send_message(self.sock, json.dumps({'type': 'close'}).encode())
                    break
                self.our_seq += 1
                seqno = self.our_seq
                ts_ms = int(time.time() * 1000)
                iv, ct = aes_encrypt(self.session_key, plaintext.encode())
                combined = iv + ct
                ct_b64 = base64.b64encode(combined).decode()
                sig = self.sign_message_bytes(seqno, ts_ms, combined)
                sig_b64 = base64.b64encode(sig).decode()
                msg = {'type': 'msg', 'seqno': seqno, 'ts': ts_ms, 'ct': ct_b64, 'sig': sig_b64}
                send_message(self.sock, json.dumps(msg).encode())
                self.append_transcript_line(seqno, ts_ms, ct_b64, sig_b64)
        except Exception as e:
            print('Sender loop error:', e)
            self.running = False

    def receiver_loop(self):
        try:
            while self.running:
                raw = recv_message(self.sock)
                payload = json.loads(raw.decode())
                if payload.get('type') == 'msg':
                    seqno = int(payload['seqno'])
                    ts_ms = int(payload['ts'])
                    ct_b64 = payload['ct']
                    sig_b64 = payload['sig']
                    combined = base64.b64decode(ct_b64)
                    sig = base64.b64decode(sig_b64)
                    if seqno <= self.peer_last_seq:
                        print('Replay/old message detected, dropping')
                        continue
                    ok = self.verify_peer_signature(seqno, ts_ms, combined, sig)
                    if not ok:
                        print('BAD SIGNATURE: message rejected')
                        continue
                    iv = combined[:16]
                    ct = combined[16:]
                    try:
                        pt = aes_decrypt(self.session_key, iv, ct)
                    except Exception as e:
                        print('Decryption failed:', e)
                        continue
                    print(f'Peer> {pt.decode()}')
                    self.peer_last_seq = seqno
                    self.append_transcript_line(seqno, ts_ms, ct_b64, sig_b64)
                elif payload.get('type') == 'close':
                    print('Peer initiated close')
                    self.running = False
                    break
                elif payload.get('type') == 'receipt':
                    # verify peer receipt
                    txhex = payload.get('transcript_sha256')
                    sig_b64 = payload.get('sig')
                    sig = base64.b64decode(sig_b64)
                    try:
                        self.peer_pubkey.verify(sig, bytes.fromhex(txhex), padding.PKCS1v15(), hashes.SHA256())
                        print('Peer receipt verified OK')
                    except Exception as e:
                        print('Peer receipt verification FAILED:', e)
                else:
                    print('Unknown message:', payload)
        except Exception as e:
            print('Receiver loop error:', e)
            self.running = False

    def finalize_and_send_receipt(self):
        if os.path.exists(TRANSCRIPT_FILE):
            with open(TRANSCRIPT_FILE, 'rb') as f:
                all_bytes = f.read()
        else:
            all_bytes = b''
        tx_hash = hashlib.sha256(all_bytes).digest()
        tx_hex = tx_hash.hex()
        sig = self.privkey.sign(tx_hash, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.b64encode(sig).decode()
        receipt = {'type': 'receipt', 'peer': 'client', 'first_seq': 1 if self.transcript_lines else 0,
                   'last_seq': self.our_seq if self.transcript_lines else 0,
                   'transcript_sha256': tx_hex, 'sig': sig_b64}
        with open(RECEIPT_FILE, 'w') as f:
            json.dump(receipt, f, indent=2)
        try:
            send_message(self.sock, json.dumps(receipt).encode())
        except Exception:
            pass

# ---------- Registration/login helpers (DH over TLS + AES) ----------
def perform_register_or_login(tls_sock, action, email=None, username=None, password=None):
    # Server sends B, client responds with A -> derive AES -> send encrypted payload (iv||ct)
    # Receive server public B
    server_B_bytes = recv_message(tls_sock)
    B = int.from_bytes(server_B_bytes, 'big')
    a = randbelow(p - 2) + 2
    A = pow(g, a, p)
    A_bytes = A.to_bytes(INT_LEN, 'big')
    send_message(tls_sock, A_bytes)
    Ks = pow(B, a, p)
    aes_key = derive_session_key_from_Ks(Ks)
    # build payload
    payload = {'action': action}
    if action == 'register':
        payload.update({'email': email, 'username': username, 'password': password})
    else:
        payload.update({'username': username, 'password': password})
    pt = json.dumps(payload).encode()
    iv, ct = aes_encrypt(aes_key, pt)
    send_message(tls_sock, iv + ct)
    resp_raw = recv_message(tls_sock)
    return json.loads(resp_raw.decode())

# ---------- main client run ----------
def run_client():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.check_hostname = False  # set True if real hostname and matching cert

    sock = socket.create_connection((HOST, PORT))
    ssock = context.wrap_socket(sock, server_hostname='server.example.local')
    peer_cert_der = ssock.getpeercert(binary_form=True)
    if not peer_cert_der:
        print('No server certificate presented, abort')
        ssock.close()
        return

    # Example: register or login
    print('Choose: 1) register 2) login')
    choice = input('> ').strip()
    if choice == '1':
        email = input('email: ').strip()
        username = input('username: ').strip()
        password = input('password: ').strip()
        resp = perform_register_or_login(ssock, 'register', email=email, username=username, password=password)
        print('Register response:', resp)
        ssock.close()
        return
    else:
        username = input('username: ').strip()
        password = input('password: ').strip()
        resp = perform_register_or_login(ssock, 'login', username=username, password=password)
        print('Login response:', resp)
        if resp.get('status') != 'ok':
            ssock.close()
            return

    # login succeeded -> establish chat session key (classical DH)
    client_priv = load_private_key(CLIENT_KEY)
    client = ChatClient(ssock, peer_cert_der, client_priv)
    client.classical_dh_exchange()

    # start threads
    r = threading.Thread(target=client.receiver_loop, daemon=True)
    s = threading.Thread(target=client.sender_loop, daemon=True)
    r.start()
    s.start()
    s.join()
    r.join()

    # finalize receipts
    client.finalize_and_send_receipt()
    time.sleep(0.5)
    ssock.close()

if __name__ == '__main__':
    run_client()
