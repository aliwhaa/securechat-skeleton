#!/usr/bin/env python3
"""
app/storage/transcript.py

Append-only transcript manager.

Transcript file format (one line per message):
    seqno|ts|ct_b64|sig_b64|peer_cert_fingerprint_hex\n

Functions:
- start_transcript(session_id) -> file path
- append_entry(session_id, seqno, ts, ct_b64, sig_b64, peer_cert_fingerprint) -> None
- compute_transcript_hash(session_id) -> hex string (sha256 of concatenation of lines bytes)
- export_transcript(session_id, out_path=None) -> path to saved transcript file
- create_session_receipt(session_id, signer_privkey_path, peer_label="client"|"server") -> dict (receipt)
- save_receipt(session_id, receipt_dict, out_path=None) -> writes JSON
"""

import os
import hashlib
import json
import logging
from typing import Optional
from datetime import datetime
from app.crypto import sign as sign_module
from app.crypto import pki as pki_module
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TRANSCRIPTS_DIR = os.getenv("TRANSCRIPTS_DIR", "transcripts")
os.makedirs(TRANSCRIPTS_DIR, exist_ok=True)


def _transcript_path(session_id: str) -> str:
    """Return path to transcript file for a given session_id."""
    safe = session_id.replace("/", "_")
    return os.path.join(TRANSCRIPTS_DIR, f"session-{safe}.log")


def start_transcript(session_id: str) -> str:
    """
    Create (or truncate) a transcript file and return its path.
    Use this at session start.
    """
    path = _transcript_path(session_id)
    # create empty file if not present
    with open(path, "wb") as f:
        pass
    logger.info("Started transcript: %s", path)
    return path


def append_entry(session_id: str, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_cert_fingerprint_hex: str):
    """
    Append a single transcript line in the exact canonical format:
        seqno|ts|ct_b64|sig_b64|peer_cert_fingerprint_hex\n

    All fields are written as ASCII (utf-8). The function opens the file in append-binary mode
    and writes the line bytes. This exact formatting is relied upon by offline verification.
    """
    path = _transcript_path(session_id)
    line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_cert_fingerprint_hex}\n"
    with open(path, "ab") as f:
        f.write(line.encode("utf-8"))
    logger.debug("Appended transcript entry (session=%s seq=%s)", session_id, seqno)


def compute_transcript_hash(session_id: str) -> str:
    """
    Compute SHA-256 over the concatenation of transcript file lines (raw bytes).
    Returns the hex digest string (lower-case).
    """
    path = _transcript_path(session_id)
    if not os.path.exists(path):
        return hashlib.sha256(b"").hexdigest()
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def export_transcript(session_id: str, out_path: Optional[str] = None) -> str:
    """
    Copy the transcript file to out_path (or to transcripts/session-<id>-export.log).
    Return the path to the exported file.
    """
    src = _transcript_path(session_id)
    if not os.path.exists(src):
        raise FileNotFoundError("Transcript not found for session_id: " + session_id)

    if out_path is None:
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_path = os.path.join(TRANSCRIPTS_DIR, f"session-{session_id}-export-{timestamp}.log")

    with open(src, "rb") as sf, open(out_path, "wb") as df:
        df.write(sf.read())

    logger.info("Exported transcript to %s", out_path)
    return out_path


def create_session_receipt(session_id: str, signer_private_key_pem_path: str, peer_label: str = "client") -> dict:
    """
    Create a signed SessionReceipt for the given transcript/session.

    Steps:
      - Compute transcript SHA-256 (hex)
      - Load private key (PEM) and sign the raw digest bytes (binary)
        NOTE: sign_module.sign_bytes expects a private key object and signs raw bytes.
      - Return a dictionary:
        {
          "type": "receipt",
          "peer": peer_label,
          "first_seq": <int>,
          "last_seq": <int>,
          "transcript_sha256": "<hex>",
          "sig": "<base64 signature>"
        }

    The signer_private_key_pem_path should point to a PEM file containing the RSA private key.
    """
    # compute transcript hash (hex) & raw bytes
    transcript_hex = compute_transcript_hash(session_id)
    transcript_bytes = bytes.fromhex(transcript_hex)  # 32 raw bytes

    # compute first/last seq by reading file
    path = _transcript_path(session_id)
    first_seq = None
    last_seq = None
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("|")
                try:
                    seq = int(parts[0])
                except Exception:
                    continue
                if first_seq is None:
                    first_seq = seq
                last_seq = seq

    if first_seq is None:
        first_seq = 0
    if last_seq is None:
        last_seq = 0

    # load signer private key
    priv = sign_module.load_private_key_pem(signer_private_key_pem_path)

    # sign the raw transcript bytes (not hex string)
    signature = sign_module.sign_bytes(priv, transcript_bytes)
    sig_b64 = base64.b64encode(signature).decode("ascii")

    receipt = {
        "type": "receipt",
        "peer": peer_label,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hex,
        "sig": sig_b64,
    }
    return receipt


def save_receipt(session_id: str, receipt: dict, out_path: Optional[str] = None) -> str:
    """
    Save receipt dict as JSON to file and return path.
    Default path: transcripts/session-<id>-receipt.json
    """
    if out_path is None:
        out_path = os.path.join(TRANSCRIPTS_DIR, f"session-{session_id}-receipt.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2)
    logger.info("Saved receipt to %s", out_path)
    return out_path

