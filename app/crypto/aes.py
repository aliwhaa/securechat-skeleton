"""
AES-128 (ECB) + PKCS#7 helpers.

Functions:
- pad_pkcs7(data, block_size=16)
- unpad_pkcs7(padded, block_size=16)
- encrypt_aes_ecb(key16, plaintext) -> ciphertext bytes
- decrypt_aes_ecb(key16, ciphertext) -> plaintext bytes

Note: ECB mode is used because the assignment explicitly requests AES-128(ECB).
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()


def unpad_pkcs7(padded: bytes, block_size: int = 16) -> bytes:
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _validate_key(key: bytes):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Key must be bytes")
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes long")


def encrypt_aes_ecb(key16: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-ECB with PKCS#7 padding.
    Returns raw ciphertext bytes.
    """
    _validate_key(key16)
    padded = pad_pkcs7(plaintext, block_size=16)
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct


def decrypt_aes_ecb(key16: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-ECB and remove PKCS#7 padding.
    Returns plaintext bytes.
    Raises ValueError on bad padding / decryption errors.
    """
    _validate_key(key16)
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad_pkcs7(padded, block_size=16)
    return plaintext

