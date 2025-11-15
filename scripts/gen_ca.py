"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def make_ca(out_dir: str, common_name: str, days: int = 3650, key_size: int = 4096):
    os.makedirs(out_dir, exist_ok=True)
    # generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    key_path = os.path.join(out_dir, "ca.key.pem")
    cert_path = os.path.join(out_dir, "ca.cert.pem")

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated CA key -> {key_path}")
    print(f"Generated CA cert -> {cert_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a self-signed root CA certificate and key")
    parser.add_argument("--out-dir", default="certs", help="Directory to save key and cert")
    parser.add_argument("--cn", default="Local Test CA", help="Common Name for CA certificate")
    parser.add_argument("--days", type=int, default=3650, help="Validity period in days")
    parser.add_argument("--key-size", type=int, default=4096, help="RSA key size in bits")
    args = parser.parse_args()

    make_ca(args.out_dir, args.cn, args.days, args.key_size)






