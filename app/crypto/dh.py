"""
Classic Diffie-Hellman helpers.

Implements:
- generate_private_key(num_bits=2048) -> int
- compute_public(p, g, private_int) -> int
- compute_shared(p, other_public_int, private_int) -> int
- derive_aes_key_from_shared(shared_int) -> 16-byte AES key per spec:
    K = Trunc16(SHA256(big-endian(Ks)))
"""

import secrets
import hashlib


def generate_private_key(num_bits: int = 2044) -> int:
    """
    Generate a random private exponent of approximately num_bits length.
    Using secrets.randbits ensures cryptographic randomness.
    """
    # ensure it's at least 256 bits even if caller passes smaller
    if num_bits < 256:
        num_bits = 256
    priv = secrets.randbits(num_bits)
    # ensure private != 0
    if priv == 0:
        return generate_private_key(num_bits)
    return priv


def compute_public(p: int, g: int, private_int: int) -> int:
    """
    Compute public value A = g^a mod p
    """
    return pow(g, private_int, p)


def compute_shared(p: int, other_public_int: int, private_int: int) -> int:
    """
    Compute shared secret Ks = other_public^private mod p
    """
    return pow(other_public_int, private_int, p)


def _int_to_big_endian_bytes(x: int) -> bytes:
    """
    Convert integer to big-endian bytes with minimal length (no leading zero bytes).
    """
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, byteorder="big")


def derive_aes_key_from_shared(shared_int: int) -> bytes:
    """
    Derive AES-128 key (16 bytes) from DH shared secret integer:
        K = Trunc16(SHA256(big-endian(Ks)))
    """
    ks_bytes = _int_to_big_endian_bytes(shared_int)
    h = hashlib.sha256(ks_bytes).digest()
    return h[:16]

