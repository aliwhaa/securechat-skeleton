"""
app/crypto/aes.py

AES-128 (ECB) with PKCS#7 padding helpers.

Provides:
- pad_pkcs7(data, block_size=16) -> bytes
- unpad_pkcs7(padded, block_size=16) -> bytes
- encrypt_aes_ecb(key16, plaintext) -> ciphertext bytes
- decrypt_aes_ecb(key16, ciphertext) -> plaintext bytes

Notes:
- The assignment explicitly requires AES-128 in ECB mode with PKCS#7 padding.
- Functions work on raw bytes. JSON transport should base64-encode ciphertext/sigs elsewhere.
- Raises ValueError for invalid key sizes or bad padding during decryption.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from typing import ByteString


def pad_pkcs7(data: ByteString, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to `data` to make its length a multiple of block_size.
    Returns padded bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    padder = sym_padding.PKCS7(block_size * 8).padder()
    return padder.update(bytes(data)) + padder.finalize()


def unpad_pkcs7(padded: ByteString, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding. Raises ValueError on bad padding.
    """
    if not isinstance(padded, (bytes, bytearray)):
        raise TypeError("padded must be bytes or bytearray")
    unpadder = sym_padding.PKCS7(block_size * 8).unpadder()
    try:
        return unpadder.update(bytes(padded)) + unpadder.finalize()
    except ValueError as e:
        # Re-raise with a clearer message for caller
        raise ValueError("Invalid PKCS#7 padding or corrupted ciphertext") from e


def _validate_key(key: ByteString):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("AES key must be bytes")
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes long")


def encrypt_aes_ecb(key16: ByteString, plaintext: ByteString) -> bytes:
    """
    Encrypt plaintext with AES-128 in ECB mode using PKCS#7 padding.
    Returns raw ciphertext bytes.
    """
    _validate_key(key16)
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    padded = pad_pkcs7(plaintext, block_size=16)
    cipher = Cipher(algorithms.AES(bytes(key16)), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct


def decrypt_aes_ecb(key16: ByteString, ciphertext: ByteString) -> bytes:
    """
    Decrypt ciphertext with AES-128-ECB and remove PKCS#7 padding.
    Returns plaintext bytes. Raises ValueError on bad padding or invalid key.
    """
    _validate_key(key16)
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    cipher = Cipher(algorithms.AES(bytes(key16)), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(bytes(ciphertext)) + decryptor.finalize()
    plaintext = unpad_pkcs7(padded, block_size=16)
    return plaintext


# Small self-test when module executed directly
if __name__ == "__main__":
    key = b"\x00" * 16
    msg = b"The quick brown fox jumps over the lazy dog"
    ct = encrypt_aes_ecb(key, msg)
    pt = decrypt_aes_ecb(key, ct)
    assert pt == msg
    print("AES-128-ECB self-test OK. ciphertext len:", len(ct))

