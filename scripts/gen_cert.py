#!/usr/bin/env python3

"""
Generate a certificate signed by SecureChat Root CA.
Usage:
    python scripts/gen_cert.py --cn server.local --out certs/server
Produces:
    <out>.key
    <out>.crt
"""

import argparse
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True, help="Common Name for the certificate")
    parser.add_argument("--out", required=True, help="Output path without extension")
    args = parser.parse_args()

    cn = args.cn
    out = args.out

    os.makedirs(os.path.dirname(out), exist_ok=True)

    # --- Load CA private key ---
    with open("certs/ca.key", "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    # --- Load CA certificate ---
    with open("certs/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # --- Generate user/server private key ---
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(out + ".key", "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # --- Build certificate ---
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )

    with open(out + ".crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Certificate generated for CN={cn}:")
    print(f"    {out}.key")
    print(f"    {out}.crt")


if __name__ == "__main__":
    main()

