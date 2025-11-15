"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import ssl
import socket
import json
import os
import hashlib
import struct
import pymysql
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

# CONFIG
HOST = '0.0.0.0'
PORT = 8443
CERT_DIR = 'certs'
CA_CERT = os.path.join(CERT_DIR, 'ca.cert.pem')
SERVER_CERT = os.path.join(CERT_DIR, 'server.cert.pem')
SERVER_KEY = os.path.join(CERT_DIR, 'server.key.pem')

# MySQL config - change for your environment
MYSQL_HOST = '127.0.0.1'
MYSQL_PORT = 3306
MYSQL_USER = 'scuser'
MYSQL_PASS = 'scpass'
MYSQL_DB = 'securechat'

# Helper network helpers

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError('Connection closed')
        data += chunk
    return data


def recv_message(sock):
    # 4-byte length prefix
    raw = recv_exact(sock, 4)
    (l,) = struct.unpack('!I', raw)
    return recv_exact(sock, l)


def send_message(sock, b):
    sock.sendall(struct.pack('!I', len(b)) + b)


# AES helpers

def derive_aes128_from_shared(shared_bytes):
    digest = hashlib.sha256(shared_bytes).digest()
    return digest[:16]


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


# MySQL helpers

def get_db_connection():
    return pymysql.connect(host=MYSQL_HOST, port=MYSQL_PORT, user=MYSQL_USER, password=MYSQL_PASS, database=MYSQL_DB)


def handle_register(payload_json, db_conn):
    email = payload_json.get('email')
    username = payload_json.get('username')
    password = payload_json.get('password')
    if not (email and username and password):
        return {'status': 'error', 'reason': 'missing_fields'}

    with db_conn.cursor() as cur:
        # check email or username
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


# Main server

def run_server():
    # Prepare TLS context for mutual TLS
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED

    # Create raw socket
    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind((HOST, PORT))
    bindsock.listen(5)
    print('Server listening on', (HOST, PORT))

    # DH parameters (can be reused safely for multiple sessions)
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    db_conn = get_db_connection()

    try:
        while True:
            newsock, addr = bindsock.accept()
            try:
                conn = context.wrap_socket(newsock, server_side=True)
                print('TLS handshake complete with', addr)

                # Verify peer certificate is present and trusted
                peer_cert = conn.getpeercert()
                if not peer_cert:
                    print('BAD CERT: no peer certificate')
                    conn.close()
                    continue
                # At this point the TLS layer already validated chain against CA

                # 1) DH key exchange (send server pub, receive client pub)
                server_private = parameters.generate_private_key()
                server_public = server_private.public_key()
                server_pub_bytes = server_public.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                send_message(conn, server_pub_bytes)
                client_pub_bytes = recv_message(conn)
                client_public = serialization.load_der_public_key(client_pub_bytes)
                shared = server_private.exchange(client_public)

                # derive AES key
                aes_key = derive_aes128_from_shared(shared)

                # 2) receive encrypted payload (IV + ciphertext)
                enc_blob = recv_message(conn)
                # enc_blob format: IV (16 bytes) || ciphertext
                iv = enc_blob[:16]
                ct = enc_blob[16:]
                try:
                    plaintext = aes_decrypt(aes_key, iv, ct)
                except Exception as e:
                    print('Decryption failed:', e)
                    send_message(conn, b'')
                    conn.close()
                    continue

                payload_json = json.loads(plaintext.decode())
                action = payload_json.get('action')
                if action == 'register':
                    resp = handle_register(payload_json, db_conn)
                elif action == 'login':
                    resp = handle_login(payload_json, db_conn)
                else:
                    resp = {'status': 'error', 'reason': 'unknown_action'}

                send_message(conn, json.dumps(resp).encode())
                conn.close()
            except Exception as e:
                print('Connection handling error:', e)
                try:
                    newsock.close()
                except:
                    pass
    finally:
        db_conn.close()


if __name__ == '__main__':
    run_server()
