"""
PKI helpers: load certs/keys, certificate validation against a CA cert,
and utility functions like fingerprint.

Functions:
- load_certificate(path_or_bytes) -> cryptography.x509.Certificate
- load_private_key(path_or_bytes) -> private key object
- validate_certificate(cert, ca_cert, expected_cn=None) -> (True, None) or (False, reason)
- cert_sha256_fingerprint_hex(cert) -> hex string of SHA256 over DER
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.x509.oid import NameOID
from datetime import datetime


def load_certificate(pem_or_path):
    if isinstance(pem_or_path, (bytes, bytearray)):
        return x509.load_pem_x509_certificate(pem_or_path)
    with open(pem_or_path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)


def load_private_key(pem_or_path, password=None):
    if isinstance(pem_or_path, (bytes, bytearray)):
        data = pem_or_path
    else:
        with open(pem_or_path, "rb") as f:
            data = f.read()
    return serialization.load_pem_private_key(data, password=password)


def cert_sha256_fingerprint_hex(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def _verify_signature_chain(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """
    Verify that cert was signed by issuer_cert (checks signature only).
    """
    pubkey = issuer_cert.public_key()
    try:
        pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asympadding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def validate_certificate(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str = None):
    """
    Validate a certificate against the provided CA certificate.

    Returns (True, None) on success, or (False, "reason") on failure.

    Checks performed:
    - Signature: cert signed by CA
    - Validity period: not before <= now <= not after
    - If expected_cn provided: CN on cert must match
    """
    # Signature chain check
    if not _verify_signature_chain(cert, ca_cert):
        return False, "BAD_CERT: signature verification failed (not signed by CA)"

    # Validity (dates)
    now = datetime.utcnow()
    if cert.not_valid_before > now:
        return False, "BAD_CERT: certificate not yet valid"
    if cert.not_valid_after < now:
        return False, "BAD_CERT: certificate expired"

    # CN check if requested
    if expected_cn is not None:
        try:
            cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            return False, "BAD_CERT: CN missing"
        if cn_attr != expected_cn:
            return False, f"BAD_CERT: CN mismatch (expected {expected_cn}, got {cn_attr})"

    return True, None

