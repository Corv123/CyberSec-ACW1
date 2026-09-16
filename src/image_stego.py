"""
image_stego.py -- Person1 (FR1 image input, FR5 image embedding, FR8 image extraction)

Team API (import from this module):
  check_capacity, embed_image, extract_image, make_tampered_image

Depends on:
- crypto_utils.pack() / unpack() for the byte blob format (ALIGNMENT.md Section 4)
- start_location.derive_start_location() for where to begin (Person3)

Hands off to:
- gui_app.py calls embed_image() / extract_image() / make_tampered_image()
- verdict.py consumes extract_image() output (via crypto unpack/verify)

Indexing: flat R,G,B sample index, row-major (pixel0 R,G,B, pixel1 R,G,B, ...).
Embed/extract treat `blob` as opaque bytes from crypto_utils.pack():
  [4-byte big-endian N][N JSON payload bytes][256-byte RSA signature]

Self-test from repo root (same idea as crypto_utils.py):
  python src/image_stego.py
  python src/image_stego.py --tamper
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from PIL import Image

# Fixed RSA-2048 signature length (same as crypto_utils.SIGNATURE_LEN).
SIGNATURE_LEN = 256
_LENGTH_STRUCT = struct.Struct(">I")


class ImageStegoError(Exception):
    """Base error for image steganography."""


class InvalidImageError(ImageStegoError):
    """Image could not be loaded or is unsupported."""


class PayloadTooLargeError(ImageStegoError):
    """Blob exceeds cover capacity from start location and LSB depth."""


class ExtractionError(ImageStegoError):
    """Hidden blob could not be read."""


def _load_rgb(path: str | Path) -> Image.Image:
    path = Path(path)
    if not path.is_file():
        raise InvalidImageError(f"File not found: {path}")
    try:
        with Image.open(path) as im:
            return im.convert("RGB")
    except OSError as exc:
        raise InvalidImageError(f"Cannot read image: {path}") from exc


def _flatten_rgb(image: Image.Image) -> list[int]:
    flat: list[int] = []
    for r, g, b in image.getdata():
        flat.extend((r, g, b))
    return flat


def _unflatten_rgb(flat: list[int], width: int, height: int) -> Image.Image:
    if len(flat) != width * height * 3:
        raise InvalidImageError("Sample count does not match image dimensions.")
    pixels = [(flat[i], flat[i + 1], flat[i + 2]) for i in range(0, len(flat), 3)]
    out = Image.new("RGB", (width, height))
    out.putdata(pixels)
    return out


def _bytes_available(sample_count: int, start_location: int, lsb_depth: int) -> int:
    if start_location < 0 or lsb_depth < 1 or lsb_depth > 8:
        return 0
    if start_location >= sample_count:
        return 0
    return ((sample_count - start_location) * lsb_depth) // 8


def _bytes_to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ExtractionError("Bit stream length is not a multiple of 8.")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)


def _embed_bytes(
    samples: list[int],
    data: bytes,
    *,
    start_location: int,
    lsb_depth: int,
) -> list[int]:
    if lsb_depth < 1 or lsb_depth > 8:
        raise ValueError("lsb_depth must be between 1 and 8.")
    if start_location < 0 or start_location >= len(samples):
        raise ValueError("start_location out of range.")

    bits = _bytes_to_bits(data)
    mask = (1 << lsb_depth) - 1
    clear_mask = (~mask) & 0xFF
    bit_idx = 0
    total_bits = len(bits)
    out = samples[:]

    for i in range(start_location, len(out)):
        if bit_idx >= total_bits:
            break
        chunk = 0
        for _ in range(lsb_depth):
            if bit_idx < total_bits:
                chunk |= bits[bit_idx] << _
                bit_idx += 1
        out[i] = (out[i] & clear_mask) | chunk

    if bit_idx < total_bits:
        raise PayloadTooLargeError(
            f"Need {total_bits} bits but only {bit_idx} fit from start_location={start_location}."
        )
    return out


def _extract_bytes(
    samples: list[int],
    byte_count: int,
    *,
    start_location: int,
    lsb_depth: int,
) -> bytes:
    if lsb_depth < 1 or lsb_depth > 8:
        raise ValueError("lsb_depth must be between 1 and 8.")
    if byte_count < 0:
        raise ValueError("byte_count must be non-negative.")

    mask = (1 << lsb_depth) - 1
    bits: list[int] = []
    bits_needed = byte_count * 8
    bit_idx = 0

    for i in range(start_location, len(samples)):
        if bit_idx >= bits_needed:
            break
        value = samples[i] & mask
        for b in range(lsb_depth):
            if bit_idx >= bits_needed:
                break
            bits.append((value >> b) & 1)
            bit_idx += 1

    if bit_idx < bits_needed:
        raise ExtractionError(
            f"Need {bits_needed} bits but only read {bit_idx} from cover."
        )
    return _bits_to_bytes(bits)


def check_capacity(
    cover_path: str,
    payload_size_bytes: int,
    lsb_depth: int,
    start_location: int = 0,
) -> bool:
    """Return True if `payload_size_bytes` fit in the cover.

    Pass the full embed size (e.g. crypto_utils.total_embed_size(payload) or
    len(blob)), not the JSON length alone. Optional start_location defaults to 0.
    """
    if payload_size_bytes < 0:
        return False
    im = _load_rgb(cover_path)
    w, h = im.size
    sample_count = w * h * 3
    return payload_size_bytes <= _bytes_available(sample_count, start_location, lsb_depth)


def embed_image(
    cover_path: str,
    blob: bytes,
    start_location: int,
    lsb_depth: int,
    output_path: str,
) -> str:
    """FR5: embed packed blob into PNG cover using LSB replacement. Always saves PNG."""
    im = _load_rgb(cover_path)
    w, h = im.size
    samples = _flatten_rgb(im)

    if not check_capacity(cover_path, len(blob), lsb_depth, start_location):
        raise PayloadTooLargeError(
            f"Blob ({len(blob)} bytes) exceeds capacity from "
            f"start_location={start_location}, lsb_depth={lsb_depth}."
        )

    stego_samples = _embed_bytes(
        samples, blob, start_location=start_location, lsb_depth=lsb_depth
    )
    stego = _unflatten_rgb(stego_samples, w, h)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    stego.save(out, format="PNG")
    return str(out)


def extract_image(stego_path: str, start_location: int, lsb_depth: int) -> bytes:
    """FR8: extract full packed blob [4|payload|signature] for crypto_utils.unpack()."""
    im = _load_rgb(stego_path)
    samples = _flatten_rgb(im)
    available = _bytes_available(len(samples), start_location, lsb_depth)
    if available < 4:
        raise ExtractionError("Cover too small to contain length header.")

    header = _extract_bytes(
        samples, 4, start_location=start_location, lsb_depth=lsb_depth
    )
    (payload_len,) = _LENGTH_STRUCT.unpack(header)
    total = 4 + payload_len + SIGNATURE_LEN
    if total > available:
        raise ExtractionError(
            f"Declared blob size ({total} bytes) exceeds cover capacity ({available})."
        )

    return _extract_bytes(
        samples, total, start_location=start_location, lsb_depth=lsb_depth
    )


def make_tampered_image(
    stego_path: str,
    output_path: str,
    start_location: int = 0,
    lsb_depth: int = 1,
) -> str:
    """Create a negative-case sample: flip one pixel inside the embedded blob body.

    Does not verify signatures — Person5/Person4 handle Extract -> Verify -> Verdict.
    Person6 can call this from the GUI to generate FR11 negative evidence.
    """
    if lsb_depth < 1 or lsb_depth > 8:
        raise ValueError("lsb_depth must be between 1 and 8.")

    # Skip length header (4 bytes = 32 bits → ceil(32 / lsb_depth) samples),
    # then step a little into the payload body.
    header_samples = (32 + lsb_depth - 1) // lsb_depth
    body_sample = start_location + header_samples + 8

    im = _load_rgb(stego_path)
    width, height = im.size
    pixel_index = body_sample // 3
    channel = body_sample % 3
    x = pixel_index % width
    y = pixel_index // width
    if y >= height:
        x, y, channel = width // 2, height // 2, 0

    pixels = im.load()
    before = pixels[x, y]
    rgb = list(before)
    rgb[channel] ^= 1
    pixels[x, y] = (rgb[0], rgb[1], rgb[2])

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    im.save(out, format="PNG")
    return str(out)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _ensure_keys(root: Path) -> None:
    from crypto_utils import generate_keypair

    priv = root / "keys" / "private_key.pem"
    pub = root / "keys" / "public_key.pem"
    if priv.is_file() and pub.is_file():
        return
    generate_keypair(priv_path=str(priv), pub_path=str(pub))
    print(f"Generated demo keys in {root / 'keys'}")


def _run_positive_selftest(
    *,
    start_location: int = 100,
    lsb_depth: int = 2,
) -> None:
    """Protect cover -> extract blob -> verify signature (smoke for Person1+5)."""
    from crypto_utils import (
        build_payload,
        compute_hash,
        load_private_key,
        load_public_key,
        pack,
        sign_payload,
        total_embed_size,
        unpack,
        verify_signature,
    )

    root = _repo_root()
    samples = root / "samples"
    cover = samples / "cover_image.png"
    stego = samples / "stego_image_short.png"

    if not cover.is_file():
        print(f"Missing {cover} — place a PNG cover there first.")
        sys.exit(1)

    _ensure_keys(root)
    priv = load_private_key(str(root / "keys" / "private_key.pem"))
    pub = load_public_key(str(root / "keys" / "public_key.pem"))

    # Placeholder cover_hash (whole file). Refine with Person5 per ALIGNMENT.md.
    cover_hash = compute_hash(cover.read_bytes())
    payload = build_payload(
        "IMG-0001",
        "image",
        cover_hash,
        "ACW1 image stego self-test - Person1 FR5/FR8.",
        metadata={"team": "P1-4", "lsb_depth": lsb_depth},
    )
    signature = sign_payload(payload, priv)
    blob = pack(payload, signature)

    print("FR1 — Image input")
    print(f"  cover: {cover}")
    print(f"  blob_len: {len(blob)} (4 + payload + 256 sig)")

    print("\nCapacity check")
    fits = check_capacity(
        str(cover), total_embed_size(payload), lsb_depth, start_location
    )
    print(f"  start_location={start_location}, lsb_depth={lsb_depth}")
    print(f"  total_embed_size={total_embed_size(payload)}")
    print(f"  fits: {fits}")
    if not fits:
        print("FAIL: payload too large")
        sys.exit(1)

    embed_image(str(cover), blob, start_location, lsb_depth, str(stego))
    print("\nFR5 — Embedded packed blob")
    print(f"  stego: {stego}")

    recovered_blob = extract_image(str(stego), start_location, lsb_depth)
    recovered_payload, recovered_sig = unpack(recovered_blob)
    ok = verify_signature(recovered_payload, recovered_sig, pub)

    print("\nFR8 — Extracted full blob + crypto verify")
    print(f"  blob_match: {recovered_blob == blob}")
    print(f"  signature_valid: {ok}")

    if recovered_blob != blob or not ok:
        print("\nFAIL: round-trip or signature")
        sys.exit(1)
    print("\nPASS: image embed/extract + signature OK")


def _run_tamper_only(
    *,
    start_location: int = 100,
    lsb_depth: int = 2,
) -> None:
    root = _repo_root()
    stego = root / "samples" / "stego_image_short.png"
    tampered = root / "samples" / "stego_image_tampered.png"
    if not stego.is_file():
        print(f"Missing {stego}")
        print("Run first: python src/image_stego.py")
        sys.exit(1)
    path = make_tampered_image(
        str(stego), str(tampered), start_location=start_location, lsb_depth=lsb_depth
    )
    print("Generated negative sample (tamper only)")
    print(f"  output: {path}")
    print("Hand to Person5/Person4 for Extract -> Verify -> Verdict.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Person1 image_stego self-test")
    parser.add_argument(
        "--tamper",
        action="store_true",
        help="Only write stego_image_tampered.png from existing stego (no verify)",
    )
    parser.add_argument("--start", type=int, default=100, help="start_location")
    parser.add_argument("--lsb", type=int, default=2, help="lsb_depth 1-8")
    args = parser.parse_args()
    if args.tamper:
        _run_tamper_only(start_location=args.start, lsb_depth=args.lsb)
    else:
        _run_positive_selftest(start_location=args.start, lsb_depth=args.lsb)
