#!/usr/bin/env python3

"""
Generate a Root CA for SecureChat.
Produces:
    certs/ca.key   (private key)
    certs/ca.crt   (self-signed X.509 certificate)
"""

import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes


def main():
    os.makedirs("certs", exist_ok=True)

    # --- Generate CA private key ---
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    with open("certs/ca.key", "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # --- Build CA certificate (self-signed) ---
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat-Root-CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open("certs/ca.crt", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("[+] Root CA generated:")
    print("    certs/ca.key")
    print("    certs/ca.crt")


if __name__ == "__main__":
    main()

