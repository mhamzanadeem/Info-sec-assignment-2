"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import ssl
import socket
import json
import os
import hashlib
import struct
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

# CONFIG
HOST = '127.0.0.1'
PORT = 8443
CERT_DIR = 'certs'
CA_CERT = os.path.join(CERT_DIR, 'ca.cert.pem')
CLIENT_CERT = os.path.join(CERT_DIR, 'client1.cert.pem')
CLIENT_KEY = os.path.join(CERT_DIR, 'client1.key.pem')


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


# AES helpers
import os

def derive_aes128_from_shared(shared_bytes):
    import hashlib
    digest = hashlib.sha256(shared_bytes).digest()
    return digest[:16]

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

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


# Main client flow

def perform_action(action, email=None, username=None, password=None):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.check_hostname = False  # set True if using a real hostname and SAN

    sock = socket.create_connection((HOST, PORT))
    ssock = context.wrap_socket(sock, server_hostname='server.example.local')

    # Receive server DH public key
    server_pub_bytes = recv_message(ssock)
    server_public = serialization.load_der_public_key(server_pub_bytes)

    # generate client parameters using server's parameters (extract params)
    parameters = server_public.parameters()
    client_private = parameters.generate_private_key()
    client_public = client_private.public_key()
    client_pub_bytes = client_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    send_message(ssock, client_pub_bytes)

    shared = client_private.exchange(server_public)
    aes_key = derive_aes128_from_shared(shared)

    payload = {'action': action}
    if action == 'register':
        payload.update({'email': email, 'username': username, 'password': password})
    elif action == 'login':
        payload.update({'username': username, 'password': password})

    plaintext = json.dumps(payload).encode()
    iv, ct = aes_encrypt(aes_key, plaintext)
    send_message(ssock, iv + ct)

    resp = recv_message(ssock)
    try:
        print('Server response:', json.loads(resp.decode()))
    except Exception:
        print('Server resp raw:', resp)

    ssock.close()


if __name__ == '__main__':
    # Example usage:
    # Register:
    # perform_action('register', email='hamza@example.com', username='hamza', password='secret123')
    # Login:
    # perform_action('login', username='hamza', password='secret123')
    
    # For demonstration run register then login
    perform_action('register', email='user@example.com', username='client1', password='mypassword')
    perform_action('login', username='client1', password='mypassword')

