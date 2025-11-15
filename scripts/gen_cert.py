"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509 import NameOID, SubjectAlternativeName, DNSName
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def load_ca(ca_key_path: str, ca_cert_path: str):
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def make_entity_cert(out_dir: str, cn: str, ca_key_path: str, ca_cert_path: str, days: int = 825, type_: str = "server", key_size: int = 2048):
    os.makedirs(out_dir, exist_ok=True)
    # generate entity key
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    key_path = os.path.join(out_dir, f"{cn}.key.pem")
    cert_path = os.path.join(out_dir, f"{cn}.cert.pem")

    # save private key
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # build csr
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))

    # add SAN for hostname match (helps many TLS stacks)
    csr_builder = csr_builder.add_extension(
        SubjectAlternativeName([DNSName(cn)]), critical=False
    )

    csr = csr_builder.sign(key, hashes.SHA256())

    # load CA
    ca_key, ca_cert = load_ca(ca_key_path, ca_cert_path)

    now = datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(csr.extensions.get_extension_for_class(SubjectAlternativeName).value, critical=False)
    )

    # KeyUsage and ExtendedKeyUsage depending on type
    if type_ == "server":
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False), critical=True
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False), critical=True
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated entity key -> {key_path}")
    print(f"Generated entity cert -> {cert_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an RSA keypair and sign a certificate using the local CA")
    parser.add_argument("--out-dir", default="certs", help="Directory to save key and cert")
    parser.add_argument("--cn", required=True, help="Common Name for the certificate (e.g. server.example.local or client1)")
    parser.add_argument("--ca-key", default="certs/ca.key.pem", help="Path to CA private key")
    parser.add_argument("--ca-cert", default="certs/ca.cert.pem", help="Path to CA certificate")
    parser.add_argument("--days", type=int, default=825, help="Validity period in days (<= 825 is recommended for public CAs)")
    parser.add_argument("--type", choices=["server", "client"], default="server", help="Purpose of the certificate")
    parser.add_argument("--key-size", type=int, default=2048, help="RSA key size in bits")
    args = parser.parse_args()

    make_entity_cert(args.out_dir, args.cn, args.ca_key, args.ca_cert, args.days, args.type, args.key_size)


