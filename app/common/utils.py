# app/common/utils.py
import base64
import hashlib
import time
from typing import Tuple


def b64encode_bytes(b: bytes) -> str:
    """Return base64 string (no newline)."""
    return base64.b64encode(b).decode("ascii")


def b64decode_str(s: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(s.encode("ascii"))


def now_ms() -> int:
    """Current time in unix milliseconds (int)."""
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex digest of SHA-256 for `data`."""
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Return raw bytes of SHA-256 digest."""
    return hashlib.sha256(data).digest()


def _int_to_fixed8_be(i: int) -> bytes:
    """
    Convert integer to 8-byte big-endian representation.
    Use fixed width so both sides agree on canonical format (seqno and ts).
    Raises if not representable in 8 bytes.
    """
    if i < 0:
        raise ValueError("integer must be non-negative")
    if i >= 1 << 64:
        raise ValueError("integer too large to encode in 8 bytes")
    return i.to_bytes(8, byteorder="big")


def canonical_msg_hash_bytes(seqno: int, ts: int, ct_bytes: bytes) -> bytes:
    """
    Build the canonical input to SHA-256 for per-message hashing:

        hash_input = seqno(8-byte BE) || ts(8-byte BE) || ct_bytes

    Returns the raw 32-byte SHA-256 digest (not hex).
    """
    seq_b = _int_to_fixed8_be(seqno)
    ts_b = _int_to_fixed8_be(ts)
    return sha256_bytes(seq_b + ts_b + ct_bytes)


def canonical_msg_hash_hex(seqno: int, ts: int, ct_bytes: bytes) -> str:
    """Return hex digest string for canonical message hash (used for signing)."""
    return sha256_hex(_int_to_fixed8_be(seqno) + _int_to_fixed8_be(ts) + ct_bytes)

