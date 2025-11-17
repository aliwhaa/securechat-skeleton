"""
RSA PKCS#1 v1.5 sign/verify helpers using SHA-256.

Functions:
- load_private_key_pem(path_or_bytes)
- load_public_key_from_cert(cert)  # expects cryptography.x509.Certificate
- sign_bytes(private_key, data_bytes) -> signature bytes
- verify_bytes(public_key, signature, data_bytes) -> True/False
"""

from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.exceptions import InvalidSignature


def load_private_key_pem(pem_data_or_path, password=None):
    """
    Load a private key either from bytes or from a file path.
    """
    if isinstance(pem_data_or_path, (bytes, bytearray)):
        data = pem_data_or_path
    else:
        with open(pem_data_or_path, "rb") as f:
            data = f.read()
    return serialization.load_pem_private_key(data, password=password)


def load_public_key_from_cert(cert: x509.Certificate):
    """
    Extract public key object from a cryptography.x509.Certificate
    """
    return cert.public_key()


def sign_bytes(private_key, data: bytes) -> bytes:
    """
    Sign raw data bytes with RSA PKCS#1 v1.5 and SHA-256.
    private_key is a cryptography private key object.
    """
    if not hasattr(private_key, "sign"):
        raise TypeError("private_key must be a cryptography private key object")
    signature = private_key.sign(
        data,
        asympadding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify_bytes(public_key, signature: bytes, data: bytes) -> bool:
    """
    Verify signature. Returns True if valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            asympadding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

