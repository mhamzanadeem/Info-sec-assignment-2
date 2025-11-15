# server.py
import ssl
import socket
import json
import os
import hashlib
import struct
import threading
import time
import base64
import pymysql
from secrets import randbelow
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

# ----------------- CONFIG -----------------
HOST = '0.0.0.0'
PORT = 8443
CERT_DIR = 'certs'
CA_CERT = os.path.join(CERT_DIR, 'ca.cert.pem')
SERVER_CERT = os.path.join(CERT_DIR, 'server.example.local.cert.pem')
SERVER_KEY = os.path.join(CERT_DIR, 'server.example.local.key.pem')

# MySQL config (used only for register/login steps)
MYSQL_HOST = '127.0.0.1'
MYSQL_PORT = 3306
MYSQL_USER = 'scuser'
MYSQL_PASS = 'scpass'
MYSQL_DB = 'securechat'

TRANSCRIPT_FILE = 'server_transcript.log'
RECEIPT_FILE = 'server_receipt.json'
# ------------------------------------------

# Classical DH public parameters (both sides must use same)
p = 0xE95E4A5F737059DC60DF5991D45029409E60FC09
g = 2
INT_LEN = (p.bit_length() + 7) // 8

# ---------- network framing helpers ----------
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

# ---------- crypto helpers ----------
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
    # big-endian
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

# ---------- DB helpers (same as earlier registration/login) ----------
def get_db_connection():
    return pymysql.connect(host=MYSQL_HOST, port=MYSQL_PORT, user=MYSQL_USER, password=MYSQL_PASS, database=MYSQL_DB)

def handle_register(payload_json, db_conn):
    email = payload_json.get('email')
    username = payload_json.get('username')
    password = payload_json.get('password')
    if not (email and username and password):
        return {'status': 'error', 'reason': 'missing_fields'}
    with db_conn.cursor() as cur:
        cur.execute('SELECT username FROM users WHERE username=%s OR email=%s', (username, email))
        if cur.fetchone():
            return {'status': 'error', 'reason': 'user_exists'}
        salt = os.urandom(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        cur.execute('INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)',
                    (email, username, salt, pwd_hash))
        db_conn.commit()
    return {'status': 'ok'}

def handle_login(payload_json, db_conn):
    username = payload_json.get('username')
    password = payload_json.get('password')
    if not (username and password):
        return {'status': 'error', 'reason': 'missing_fields'}
    with db_conn.cursor() as cur:
        cur.execute('SELECT salt, pwd_hash FROM users WHERE username=%s', (username,))
        row = cur.fetchone()
        if not row:
            return {'status': 'error', 'reason': 'bad_credentials'}
        salt, stored_hash = row
        computed = hashlib.sha256(salt + password.encode()).hexdigest()
        if computed == stored_hash:
            return {'status': 'ok'}
        else:
            return {'status': 'error', 'reason': 'bad_credentials'}

# ---------- Chat session functions ----------
class ChatSession:
    def __init__(self, conn, addr, peer_cert_der, server_privkey):
        self.conn = conn
        self.addr = addr
        self.peer_cert_der = peer_cert_der
        self.peer_cert, self.peer_pubkey = load_cert_pubkey_from_der(peer_cert_der)
        self.peer_fp = cert_fingerprint_hex(peer_cert_der)
        self.server_privkey = server_privkey
        self.session_key = None  # AES-128 (bytes)
        self.our_seq = 0
        self.peer_last_seq = 0
        self.transcript_lines = []  # lines appended
        self.running = True

    def classical_dh_exchange(self):
        # receive A from client (int as big-endian bytes) OR send/receive both ways
        # We'll follow a simple flow: server sends B, then receives A
        b = randbelow(p - 2) + 2
        B = pow(g, b, p)
        B_bytes = B.to_bytes(INT_LEN, 'big')
        send_message(self.conn, B_bytes)
        A_bytes = recv_message(self.conn)
        A = int.from_bytes(A_bytes, 'big')
        Ks = pow(A, b, p)
        self.session_key = derive_session_key_from_Ks(Ks)
        print('Session key established (hex):', self.session_key.hex())

    def sign_message_bytes(self, seqno, ts_ms, ct_bytes):
        # concatenation: seqno (8b) || ts_ms (8b) || ct_bytes
        seqb = int(seqno).to_bytes(8, 'big')
        tsb = int(ts_ms).to_bytes(8, 'big')
        msg = seqb + tsb + ct_bytes
        sig = self.server_privkey.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        return sig

    def verify_peer_signature(self, seqno, ts_ms, ct_bytes, sig_bytes):
        seqb = int(seqno).to_bytes(8, 'big')
        tsb = int(ts_ms).to_bytes(8, 'big')
        msg = seqb + tsb + ct_bytes
        try:
            self.peer_pubkey.verify(sig_bytes, msg, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception as e:
            return False

    def append_transcript_line(self, seqno, ts_ms, ct_b64, sig_b64):
        line = f"{seqno}|{ts_ms}|{ct_b64}|{sig_b64}|{self.peer_fp}\n"
        # append-only write
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
                    # initiate closure
                    self.running = False
                    # send a special "close" message (so peer knows)
                    meta = {'type': 'close'}
                    send_message(self.conn, json.dumps(meta).encode())
                    break

                self.our_seq += 1
                seqno = self.our_seq
                ts_ms = int(time.time() * 1000)
                iv, ct = aes_encrypt(self.session_key, plaintext.encode())
                # send ct as iv||ct raw bytes base64 encoded in JSON
                combined = iv + ct
                ct_b64 = base64.b64encode(combined).decode()
                sig = self.sign_message_bytes(seqno, ts_ms, combined)
                sig_b64 = base64.b64encode(sig).decode()
                msg = {'type': 'msg', 'seqno': seqno, 'ts': ts_ms, 'ct': ct_b64, 'sig': sig_b64}
                send_message(self.conn, json.dumps(msg).encode())
                # append transcript (line includes peer fingerprint)
                self.append_transcript_line(seqno, ts_ms, ct_b64, sig_b64)
        except Exception as e:
            print('Sender loop error:', e)
            self.running = False

    def receiver_loop(self):
        try:
            while self.running:
                raw = recv_message(self.conn)
                payload = json.loads(raw.decode())
                if payload.get('type') == 'msg':
                    seqno = int(payload['seqno'])
                    ts_ms = int(payload['ts'])
                    ct_b64 = payload['ct']
                    sig_b64 = payload['sig']
                    combined = base64.b64decode(ct_b64)
                    sig = base64.b64decode(sig_b64)
                    # replay protection
                    if seqno <= self.peer_last_seq:
                        print('Replay or old message detected, dropping')
                        continue
                    # verify signature
                    ok = self.verify_peer_signature(seqno, ts_ms, combined, sig)
                    if not ok:
                        print('BAD SIGNATURE: message rejected')
                        continue
                    # decrypt
                    iv = combined[:16]
                    ct = combined[16:]
                    try:
                        pt = aes_decrypt(self.session_key, iv, ct)
                    except Exception as e:
                        print('Decryption failed:', e)
                        continue
                    print(f'Peer> {pt.decode()}')
                    self.peer_last_seq = seqno
                    # append transcript
                    self.append_transcript_line(seqno, ts_ms, ct_b64, sig_b64)
                elif payload.get('type') == 'close':
                    print('Peer initiated close')
                    self.running = False
                    break
                elif payload.get('type') == 'receipt':
                    # peer sending receipt: verify it
                    peer = payload.get('peer')
                    first_seq = payload.get('first_seq')
                    last_seq = payload.get('last_seq')
                    txhex = payload.get('transcript_sha256')
                    sig_b64 = payload.get('sig')
                    sig = base64.b64decode(sig_b64)
                    # verify signature over txhex bytes (hex string)
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
        # compute transcript hash
        # read entire transcript file (server uses its own file)
        if os.path.exists(TRANSCRIPT_FILE):
            with open(TRANSCRIPT_FILE, 'rb') as f:
                all_bytes = f.read()
        else:
            all_bytes = b''
        tx_hash = hashlib.sha256(all_bytes).digest()
        tx_hex = tx_hash.hex()
        # sign the raw hash bytes with server private key
        sig = self.server_privkey.sign(tx_hash, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.b64encode(sig).decode()
        receipt = {'type': 'receipt', 'peer': 'server', 'first_seq': 1 if self.transcript_lines else 0,
                   'last_seq': self.our_seq if self.transcript_lines else 0,
                   'transcript_sha256': tx_hex, 'sig': sig_b64}
        # save locally
        with open(RECEIPT_FILE, 'w') as f:
            json.dump(receipt, f, indent=2)
        # send to peer
        try:
            send_message(self.conn, json.dumps(receipt).encode())
        except Exception:
            pass

def handle_connection(newsock, addr, db_conn, server_privkey):
    try:
        conn = newsock  # already TLS-wrapped by caller
        peer_cert_der = conn.getpeercert(binary_form=True)
        if not peer_cert_der:
            print('BAD CERT: no peer certificate')
            conn.close()
            return
        # At this point TLS validated the peer against CA

        # ----- perform ephemeral DH over TLS to obtain key for register/login ----- #
        # Server sends its DH public (DERless: send int bytes) and receives client's
        # We'll reuse earlier code: server generates parameters and does param-based exchange
        # For simplicity use classical per-assignment or re-use code from earlier server
        # Here we expect the client to send a bundle: client will expect to do register/login first
        # We'll reuse the earlier register/login server flow: receive DH pub, respond, decrypt payload

        # For backward compatibility, handle initial DH+encrypted register/login exchange
        # Server will perform: send server pubkey (we'll use parameters as private exponent via pow)
        # But for simplicity we'll reuse the previous behavior: server expects client's DH public after TLS
        # (However existing client implementation sends server pub first then client replies)
        #
        # To support existing client:
        # 1) server now expects client to perform perform_action (client will receive server DH, respond)
        # So we must replicate previous flow used in registration/login before proceeding to chat.

        # Receive: server will send its "registration DH public" then receive client public -> derive AES -> receive encrypted payload
        # We'll implement that flow here:
        # --- server part for registration/login ---
        parameters_private = randbelow(p - 2) + 2
        server_public = pow(g, parameters_private, p)
        send_message(conn, server_public.to_bytes(INT_LEN, 'big'))
        client_pub_bytes = recv_message(conn)
        client_public = int.from_bytes(client_pub_bytes, 'big')
        shared = pow(client_public, parameters_private, p)
        # derive AES key
        aes_key = derive_session_key_from_Ks(shared)
        # receive encrypted payload for register/login (iv+ct)
        enc_blob = recv_message(conn)
        iv = enc_blob[:16]
        ct = enc_blob[16:]
        try:
            plaintext = aes_decrypt(aes_key, iv, ct)
        except Exception as e:
            print('Decryption failed during reg/login:', e)
            conn.close()
            return
        payload_json = json.loads(plaintext.decode())
        action = payload_json.get('action')
        if action == 'register':
            resp = handle_register(payload_json, db_conn)
            send_message(conn, json.dumps(resp).encode())
            conn.close()
            return
        elif action == 'login':
            resp = handle_login(payload_json, db_conn)
            send_message(conn, json.dumps(resp).encode())
            if resp.get('status') != 'ok':
                conn.close()
                return
            # login success -> proceed to session key establishment (classical DH as per 2.3)
        else:
            send_message(conn, json.dumps({'status': 'error', 'reason': 'unknown_action'}).encode())
            conn.close()
            return

        # ----- Session Key Establishment (2.3) -----
        chat = ChatSession(conn, addr, peer_cert_der, server_privkey)
        chat.classical_dh_exchange()

        # Start sender and receiver threads
        recv_t = threading.Thread(target=chat.receiver_loop, daemon=True)
        send_t = threading.Thread(target=chat.sender_loop, daemon=True)
        recv_t.start()
        send_t.start()

        # Wait for both to finish
        send_t.join()
        recv_t.join()

        # On exit produce receipt, exchange
        chat.finalize_and_send_receipt()
        # try to receive peer receipt (already handled by receiver loop if peer sends)
        time.sleep(0.5)
        conn.close()
    except Exception as e:
        print('Connection handler error:', e)
        try:
            conn.close()
        except:
            pass

def run_server():
    # TLS context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED

    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind((HOST, PORT))
    bindsock.listen(5)
    print('Server listening on', (HOST, PORT))

    # Load server private key for signing receipts & messages
    server_privkey = load_private_key(SERVER_KEY)
    db_conn = get_db_connection()

    try:
        while True:
            newsock, addr = bindsock.accept()
            try:
                tls_conn = context.wrap_socket(newsock, server_side=True)
                print('TLS handshake complete with', addr)
                # handle in background thread
                t = threading.Thread(target=handle_connection, args=(tls_conn, addr, db_conn, server_privkey), daemon=True)
                t.start()
            except Exception as e:
                print('TLS wrap/accept error:', e)
                try:
                    newsock.close()
                except:
                    pass
    finally:
        db_conn.close()

if __name__ == '__main__':
    run_server()
