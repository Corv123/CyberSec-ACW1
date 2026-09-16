"""
crypto_utils.py -- Person5's module (FR3 payload generation, FR4 digital signature, FR9 hash verification)

Used by: image_stego.py, audio_stego.py, verdict.py, gui_app.py

Wire format produced by pack() -- this is what actually gets embedded by
image_stego.py / audio_stego.py:

    [4-byte big-endian length][JSON payload bytes][256-byte RSA-2048 signature]

Run this file directly for a self-test: `python crypto_utils.py`
"""

import json
import os
import hashlib
import struct
from datetime import datetime, timezone

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


SIGNATURE_LEN = 256  # bytes, fixed for a 2048-bit RSA key


# ---------- FR4: keypair management ----------

def generate_keypair(key_size=2048, priv_path="keys/private_key.pem", pub_path="keys/public_key.pem"):
    """Generate an RSA keypair once and save both files. Run this once as a team and
    commit both files to the repo -- fine for a class demo (spec Section 9 says
    demo-only keys don't need to stay secret)."""
    os.makedirs(os.path.dirname(priv_path) or ".", exist_ok=True)
    key = RSA.generate(key_size)
    with open(priv_path, "wb") as f:
        f.write(key.export_key())
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    return key, key.publickey()


def load_private_key(path="keys/private_key.pem"):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(path="keys/public_key.pem"):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


# ---------- FR3: payload generation ----------

def build_payload(media_id, cover_type, cover_hash, message, metadata=None):
    """Assemble the verification payload as bytes ready to sign and embed.
    `message` is the secret content being hidden -- this is what varies across the
    short / large / custom test cases required by the spec."""
    payload = {
        "media_id": media_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cover_type": cover_type,          # "image" or "audio"
        "cover_hash": cover_hash,          # see compute_hash() below
        "nonce": os.urandom(16).hex(),     # blocks replay of an old stego file
        "message": message,
        "metadata": metadata or {},
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def parse_payload(payload_bytes):
    return json.loads(payload_bytes.decode("utf-8"))


# ---------- FR9: hashing ----------

def compute_hash(data: bytes) -> str:
    """SHA-256 hex digest.

    IMPORTANT: don't hash the whole stego file for cover_hash -- embedding changes
    LSBs, so that hash would never match on decode. Hash only the part of the cover
    your embedding never touches (see ALIGNMENT.md Section 4)."""
    return hashlib.sha256(data).hexdigest()


def verify_hash(data: bytes, expected_hash: str) -> bool:
    return compute_hash(data) == expected_hash


# ---------- FR4: sign / verify ----------

def sign_payload(payload_bytes: bytes, private_key) -> bytes:
    h = SHA256.new(payload_bytes)
    return pkcs1_15.new(private_key).sign(h)


def verify_signature(payload_bytes: bytes, signature: bytes, public_key) -> bool:
    h = SHA256.new(payload_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ---------- wire format helpers (used by image_stego.py / audio_stego.py) ----------

def pack(payload_bytes: bytes, signature: bytes) -> bytes:
    """[4-byte length][payload][signature] -- the exact bytes that get embedded."""
    return struct.pack(">I", len(payload_bytes)) + payload_bytes + signature


def unpack(blob: bytes):
    """Reverse of pack(). Returns (payload_bytes, signature_bytes)."""
    payload_len = struct.unpack(">I", blob[:4])[0]
    payload_bytes = blob[4:4 + payload_len]
    signature = blob[4 + payload_len: 4 + payload_len + SIGNATURE_LEN]
    return payload_bytes, signature


def total_embed_size(payload_bytes: bytes) -> int:
    """Total bytes that will actually be embedded -- use this for the mandatory
    capacity check in image_stego.py / audio_stego.py."""
    return 4 + len(payload_bytes) + SIGNATURE_LEN


# ---------- self-test ----------

if __name__ == "__main__":
    priv, pub = generate_keypair()
    print("Keypair generated in keys/")

    cover_hash = compute_hash(b"pretend this is the stable part of a cover file")
    payload = build_payload("IMG-0001", "image", cover_hash, "hello world")
    sig = sign_payload(payload, priv)
    blob = pack(payload, sig)
    print(f"Embed size needed: {total_embed_size(payload)} bytes")

    recovered_payload, recovered_sig = unpack(blob)
    print("Signature valid:", verify_signature(recovered_payload, recovered_sig, pub))

    tampered = recovered_payload.replace(b"hello", b"HELLO")
    print("Tampered payload still 'valid' (should be False):",
          verify_signature(tampered, recovered_sig, pub))
