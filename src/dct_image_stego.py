"""
dct_image_stego.py -- DCT-domain image steganography (alternative to LSB)

Team API:
  check_capacity, embed_dct_image, extract_dct_image, make_tampered_dct_image

Method (8x8 block DCT on each RGB channel):
  - Split the image into non-overlapping 8x8 blocks
  - Apply OpenCV DCT to each block
  - Embed bits in mid-frequency coefficients (not DC, not highest AC)
  - Inverse DCT, clip to 0..255, save as PNG (lossless spatial output)

Why mid-band: DC is perceptually sensitive; highest AC is fragile / noisy.
Parity of rounded coefficient values carries each payload bit.

Opaque blob format matches crypto_utils.pack():
  [4-byte big-endian N][N JSON payload bytes][256-byte RSA signature]

start_location: index into the ordered list of coefficient *bit slots*
  (block-major, then RGB channel, then up to `lsb_depth` mid-band coeffs).
lsb_depth (1-8): how many mid-band coefficients per block-channel are used
  (API parallel to LSB depth; here it means "coeffs per block", not pixel LSBs).

Self-test from repo root:
  python src/dct_image_stego.py
  python src/dct_image_stego.py --tamper

Not wired into the GUI by default -- optional / innovation path beside image_stego.py.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

SIGNATURE_LEN = 256
LENGTH_HEADER_SIZE = 4
_LENGTH_STRUCT = struct.Struct(">I")

# Mid-frequency (u, v) positions inside an 8x8 DCT block (row, col).
# Ordered roughly by increasing frequency; first `lsb_depth` are used.
_MID_BAND = (
    (1, 2),
    (2, 1),
    (2, 2),
    (1, 3),
    (3, 1),
    (2, 3),
    (3, 2),
    (1, 4),
)

# Quantization step for parity embedding. Larger = more robust to IDCT+clip,
# slightly more visible distortion.
_COEFF_Q = 8.0


class DctImageStegoError(Exception):
    """Base error for DCT image steganography."""


class InvalidImageError(DctImageStegoError):
    """Image could not be loaded or is unsupported."""


class PayloadTooLargeError(DctImageStegoError):
    """Blob exceeds cover capacity from start location and coeff depth."""


class ExtractionError(DctImageStegoError):
    """Hidden blob could not be read."""


def _load_rgb(path: str | Path) -> Image.Image:
    path = Path(path)
    if not path.is_file():
        raise InvalidImageError(f"File not found: {path}")
    try:
        with Image.open(path) as im:
            # Composite onto white so transparent PNGs do not show leftover RGB junk.
            if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
                rgba = im.convert("RGBA")
                background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
                im = Image.alpha_composite(background, rgba).convert("RGB")
            else:
                im = im.convert("RGB")
            return im
    except OSError as exc:
        raise InvalidImageError(f"Cannot read image: {path}") from exc


def _image_to_channels(image: Image.Image) -> np.ndarray:
    """HxWx3 float32 array."""
    return np.asarray(image, dtype=np.float32)


def _channels_to_image(arr: np.ndarray) -> Image.Image:
    clipped = np.clip(np.rint(arr), 0, 255).astype(np.uint8)
    return Image.fromarray(clipped, mode="RGB")


def _block_origins(height: int, width: int) -> list[tuple[int, int]]:
    """Top-left corners of complete 8x8 blocks (partial edge blocks unused)."""
    return [(y, x) for y in range(0, height - 7, 8) for x in range(0, width - 7, 8)]


def _slot_count(height: int, width: int, lsb_depth: int) -> int:
    if lsb_depth < 1 or lsb_depth > 8:
        return 0
    n_blocks = (height // 8) * (width // 8)
    return n_blocks * 3 * lsb_depth  # blocks * RGB * coeffs


def dct_slot_count(cover_path: str, lsb_depth: int) -> int:
    """Addressable DCT bit-slots -- use as cover_size for start_location when method=DCT."""
    im = _load_rgb(cover_path)
    w, h = im.size
    return _slot_count(h, w, lsb_depth)


def _bytes_available(height: int, width: int, start_location: int, lsb_depth: int) -> int:
    total_bits = _slot_count(height, width, lsb_depth)
    if start_location < 0 or start_location >= total_bits:
        return 0
    return (total_bits - start_location) // 8


def _iter_slots(height: int, width: int, lsb_depth: int):
    """Yield (y0, x0, channel, coeff_index) in embed order."""
    positions = _MID_BAND[:lsb_depth]
    for y0, x0 in _block_origins(height, width):
        for ch in range(3):
            for ci, _uv in enumerate(positions):
                yield y0, x0, ch, ci


def _embed_bit_in_coeff(coeff: float, bit: int) -> float:
    """Force quantized parity of coeff to equal `bit` (robust to mild IDCT error)."""
    q = _COEFF_Q
    ival = int(np.floor(float(coeff) / q + 0.5))
    if (ival & 1) != (bit & 1):
        ival += 1
    return float(ival) * q


def _extract_bit_from_coeff(coeff: float) -> int:
    ival = int(np.floor(float(coeff) / _COEFF_Q + 0.5))
    return ival & 1


def _write_bits_into_block(
    block: np.ndarray,
    assignments: list[tuple[int, int, int]],
) -> np.ndarray:
    """Embed several (u, v, bit) assignments in one DCT/IDCT round-trip."""
    work = block.astype(np.float32).copy()
    for _ in range(16):
        dct = cv2.dct(work)
        for u, v, bit in assignments:
            dct[u, v] = _embed_bit_in_coeff(dct[u, v], bit)
        recon = np.clip(cv2.idct(dct), 0, 255).astype(np.float32)
        check = cv2.dct(recon)
        if all(_extract_bit_from_coeff(check[u, v]) == (bit & 1) for u, v, bit in assignments):
            return recon
        # Strengthen failing coeffs.
        q = _COEFF_Q
        for u, v, bit in assignments:
            if _extract_bit_from_coeff(check[u, v]) == (bit & 1):
                continue
            ival = int(np.floor(float(check[u, v]) / q + 0.5))
            ival += 2
            if (ival & 1) != (bit & 1):
                ival += 1
            dct[u, v] = float(ival) * q
        work = np.clip(cv2.idct(dct), 0, 255).astype(np.float32)
    return work


def _write_bit_into_block(block: np.ndarray, u: int, v: int, bit: int) -> np.ndarray:
    return _write_bits_into_block(block, [(u, v, bit)])


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


def check_capacity(
    cover_path: str,
    payload_size_bytes: int,
    lsb_depth: int,
    start_location: int = 0,
) -> bool:
    """Return True if payload_size_bytes fit (pass full blob / total_embed_size)."""
    if payload_size_bytes < 0 or not (1 <= lsb_depth <= 8):
        return False
    im = _load_rgb(cover_path)
    w, h = im.size
    return payload_size_bytes <= _bytes_available(h, w, start_location, lsb_depth)


def embed_dct_image(
    cover_path: str,
    blob: bytes,
    start_location: int,
    lsb_depth: int,
    output_path: str,
) -> str:
    """Embed packed blob into mid-band DCT coefficients; save stego PNG."""
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8.")

    im = _load_rgb(cover_path)
    w, h = im.size
    if not check_capacity(cover_path, len(blob), lsb_depth, start_location):
        raise PayloadTooLargeError(
            f"Blob ({len(blob)} bytes) exceeds DCT capacity from "
            f"start_location={start_location}, coeff_depth={lsb_depth}."
        )

    arr = _image_to_channels(im)
    bits = _bytes_to_bits(blob)
    slots = list(_iter_slots(h, w, lsb_depth))
    if start_location < 0 or start_location >= len(slots):
        raise ValueError("start_location out of range for DCT slots.")

    positions = _MID_BAND[:lsb_depth]
    bit_idx = 0
    # Track all coeff assignments per block-channel so later coeffs do not
    # wipe earlier ones in the same 8x8 block.
    pending: dict[tuple[int, int, int], list[tuple[int, int, int]]] = {}

    for slot_i in range(start_location, len(slots)):
        if bit_idx >= len(bits):
            break
        y0, x0, ch, ci = slots[slot_i]
        u, v = positions[ci]
        key = (y0, x0, ch)
        assigns = [t for t in pending.get(key, []) if not (t[0] == u and t[1] == v)]
        assigns.append((u, v, bits[bit_idx]))
        pending[key] = assigns
        block = arr[y0:y0 + 8, x0:x0 + 8, ch]
        arr[y0:y0 + 8, x0:x0 + 8, ch] = _write_bits_into_block(block, assigns)
        bit_idx += 1

    if bit_idx < len(bits):
        raise PayloadTooLargeError("Ran out of DCT slots before finishing the blob.")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    _channels_to_image(arr).save(out, format="PNG")
    return str(out)


def extract_dct_image(
    stego_path: str,
    start_location: int,
    lsb_depth: int,
) -> bytes:
    """Extract full packed blob [4|payload|signature] for crypto_utils.unpack()."""
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8.")

    im = _load_rgb(stego_path)
    w, h = im.size
    arr = _image_to_channels(im)
    slots = list(_iter_slots(h, w, lsb_depth))
    available = _bytes_available(h, w, start_location, lsb_depth)
    if available < LENGTH_HEADER_SIZE:
        raise ExtractionError("Cover too small to contain length header.")
    if start_location < 0 or start_location >= len(slots):
        raise ExtractionError("start_location out of range for DCT slots.")

    positions = _MID_BAND[:lsb_depth]

    def read_bytes(n: int) -> bytes:
        needed_bits = n * 8
        bits: list[int] = []
        slot_i = start_location
        while len(bits) < needed_bits:
            if slot_i >= len(slots):
                raise ExtractionError("Ran out of DCT slots while extracting.")
            y0, x0, ch, ci = slots[slot_i]
            u, v = positions[ci]
            block = arr[y0:y0 + 8, x0:x0 + 8, ch]
            dct = cv2.dct(block)
            bits.append(_extract_bit_from_coeff(dct[u, v]))
            slot_i += 1
        return _bits_to_bytes(bits)

    header = read_bytes(LENGTH_HEADER_SIZE)
    (payload_len,) = _LENGTH_STRUCT.unpack(header)
    total = LENGTH_HEADER_SIZE + payload_len + SIGNATURE_LEN
    if total > available:
        raise ExtractionError(
            f"Declared blob size ({total} bytes) exceeds DCT capacity ({available})."
        )
    return read_bytes(total)


def make_tampered_dct_image(
    stego_path: str,
    output_path: str,
    start_location: int = 0,
    lsb_depth: int = 1,
) -> str:
    """Negative sample: flip parity of one mid-band coefficient in the payload body."""
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8.")

    im = _load_rgb(stego_path)
    w, h = im.size
    arr = _image_to_channels(im)
    slots = list(_iter_slots(h, w, lsb_depth))
    positions = _MID_BAND[:lsb_depth]

    # Skip ~32 header bits, then nudge into payload body.
    body_slot = start_location + 32 + 8
    if body_slot >= len(slots):
        body_slot = max(0, len(slots) - 1)

    y0, x0, ch, ci = slots[body_slot]
    u, v = positions[ci]
    block = arr[y0:y0 + 8, x0:x0 + 8, ch]
    current = _extract_bit_from_coeff(cv2.dct(block.astype(np.float32))[u, v])
    arr[y0:y0 + 8, x0:x0 + 8, ch] = _write_bit_into_block(block, u, v, current ^ 1)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    _channels_to_image(arr).save(out, format="PNG")
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


def _run_positive_selftest(*, start_location: int = 0, lsb_depth: int = 2) -> None:
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
    stego = samples / "stego_dct_short.png"

    if not cover.is_file():
        print(f"Missing {cover}")
        sys.exit(1)

    _ensure_keys(root)
    priv = load_private_key(str(root / "keys" / "private_key.pem"))
    pub = load_public_key(str(root / "keys" / "public_key.pem"))

    cover_hash = compute_hash(cover.read_bytes())
    payload = build_payload(
        "IMG-DCT-0001",
        "image",
        cover_hash,
        "ACW1 DCT image stego self-test.",
        metadata={"team": "P1-4", "method": "dct", "coeff_depth": lsb_depth},
    )
    signature = sign_payload(payload, priv)
    blob = pack(payload, signature)

    print("DCT image input")
    print(f"  cover: {cover}")
    print(f"  blob_len: {len(blob)} (4 + payload + 256 sig)")

    fits = check_capacity(str(cover), total_embed_size(payload), lsb_depth, start_location)
    print(f"\nCapacity: start={start_location}, coeff_depth={lsb_depth}, fits={fits}")
    if not fits:
        print("FAIL: payload too large")
        sys.exit(1)

    embed_dct_image(str(cover), blob, start_location, lsb_depth, str(stego))
    print(f"\nEmbedded via DCT -> {stego}")

    recovered = extract_dct_image(str(stego), start_location, lsb_depth)
    recovered_payload, recovered_sig = unpack(recovered)
    ok = verify_signature(recovered_payload, recovered_sig, pub)
    print("\nExtract + crypto verify")
    print(f"  blob_match: {recovered == blob}")
    print(f"  signature_valid: {ok}")
    if recovered != blob or not ok:
        print("\nFAIL")
        sys.exit(1)
    print("\nPASS: DCT embed/extract + signature OK")


def _run_tamper_only(*, start_location: int = 0, lsb_depth: int = 2) -> None:
    root = _repo_root()
    stego = root / "samples" / "stego_dct_short.png"
    tampered = root / "samples" / "stego_dct_tampered.png"
    if not stego.is_file():
        print(f"Missing {stego}\nRun first: python src/dct_image_stego.py")
        sys.exit(1)
    path = make_tampered_dct_image(
        str(stego), str(tampered), start_location=start_location, lsb_depth=lsb_depth
    )
    print(f"Generated DCT negative sample\n  output: {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DCT image stego self-test")
    parser.add_argument("--tamper", action="store_true")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--lsb", type=int, default=2, help="mid-band coeffs per block (1-8)")
    args = parser.parse_args()
    if args.tamper:
        _run_tamper_only(start_location=args.start, lsb_depth=args.lsb)
    else:
        _run_positive_selftest(start_location=args.start, lsb_depth=args.lsb)
