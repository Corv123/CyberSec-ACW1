"""
audio_stego.py -- Person2's module (FR2 audio input, FR6 audio embedding, FR8 audio extraction)

Team API (import from this module):
  check_capacity, embed_audio, extract_audio, make_tampered_audio

Depends on:
- crypto_utils.pack() / unpack() for the byte blob format (ALIGNMENT.md Section 4)
- start_location.derive_start_location() for where to begin (Person3)

Hands off to:
- gui_app.py calls embed_audio() / extract_audio() / make_tampered_audio()
- verdict.py consumes extract_audio() output (via crypto unpack/verify)

Mirrors image_stego.py's API shape and exception hierarchy so gui_app.py and
verdict.py can treat both cover types the same way (ALIGNMENT.md Section 5:
"same shape as image_stego.py").

Indexing: flat byte index into raw frame data (every byte of every sample,
interleaved across channels, in file order -- the same array wave.readframes()
returns). Person3's derive_start_location(cover_size, seed) must compute
cover_size the same way this module does: nframes * nchannels * sampwidth.

Embed/extract treat `blob` as opaque bytes from crypto_utils.pack():
  [4-byte big-endian N][N JSON payload bytes][256-byte RSA signature]

Self-test:
  python src/audio_stego.py
  python src/audio_stego.py --tamper
"""

from __future__ import annotations

import argparse
import struct
import sys
import wave
from pathlib import Path

# Fixed RSA-2048 signature length (same as crypto_utils.SIGNATURE_LEN).
SIGNATURE_LEN = 256
LENGTH_HEADER_SIZE = 4  # bytes, matches struct.pack(">I", ...) in crypto_utils.pack()
_LENGTH_STRUCT = struct.Struct(">I")


class AudioStegoError(Exception):
    """Base error for audio steganography."""


class InvalidAudioError(AudioStegoError):
    """Audio file could not be loaded or is unsupported."""


class PayloadTooLargeError(AudioStegoError):
    """Blob exceeds cover capacity from start location and LSB depth."""


class ExtractionError(AudioStegoError):
    """Hidden blob could not be read."""


# ---------- internal helpers ----------

def _load_wav(path: str | Path) -> tuple[wave._wave_params, bytearray]:
    """Open a WAV/PCM file and return (params, raw_frame_bytes).

    params is wave's Params namedtuple -- needed to write back an identical
    header (sample rate, channels, sample width, etc.) later. raw_frame_bytes is
    a mutable bytearray of every byte of every sample, in file order.
    """
    path = Path(path)
    if not path.is_file():
        raise InvalidAudioError(f"File not found: {path}")
    try:
        with wave.open(str(path), "rb") as wf:
            params = wf.getparams()
            raw = wf.readframes(params.nframes)
    except (wave.Error, EOFError, OSError) as exc:
        raise InvalidAudioError(f"Cannot read WAV/PCM file: {path}") from exc
    return params, bytearray(raw)


def _write_wav(path: str | Path, params, raw_bytes: bytearray) -> None:
    """Write raw_bytes out as a WAV file with the exact same header params as
    the original cover. Only sample data changes -- the header is untouched."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(out), "wb") as wf:
        wf.setparams(params)
        wf.writeframes(bytes(raw_bytes))


def _cover_size_bytes(params) -> int:
    """Total addressable raw sample bytes -- must match how Person3's
    derive_start_location() computes cover_size for audio."""
    return params.nframes * params.nchannels * params.sampwidth


def _usable_indices(params, low_byte_only: bool) -> list[int]:
    """The raw-byte indices this module is allowed to modify.

    low_byte_only=False (default): every raw byte is usable -- matches the
    original flat-byte scheme and image_stego.py's per-channel-byte scheme.

    low_byte_only=True: only the low byte of each multi-byte sample is usable
    (a no-op for 8-bit audio). For 16-bit little-endian PCM, byte 0 of each
    2-byte sample is the low byte -- modifying only that byte instead of both
    keeps distortion roughly half of what full-byte embedding causes at the
    same lsb_depth, since the high byte (which dominates perceived loudness)
    is never touched. This roughly halves capacity in exchange for quality,
    most noticeable at lsb_depth >= 5.
    """
    total = _cover_size_bytes(params)
    if not low_byte_only or params.sampwidth <= 1:
        return list(range(total))
    return [i for i in range(total) if i % params.sampwidth == 0]


def _bytes_to_bits(data: bytes) -> str:
    return "".join(format(b, "08b") for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - (len(bits) % 8), 8):
        out.append(int(bits[i:i + 8], 2))
    return bytes(out)


def _bytes_available(usable_count: int, start_offset: int, lsb_depth: int) -> int:
    if lsb_depth < 1 or lsb_depth > 8 or start_offset < 0:
        return 0
    if start_offset >= usable_count:
        return 0
    return ((usable_count - start_offset) * lsb_depth) // 8


# ---------- FR2 + mandatory scope: capacity check ----------

def check_capacity(
    cover_path: str,
    payload_size_bytes: int,
    lsb_depth: int,
    start_location: int = 0,
    low_byte_only: bool = False,
) -> bool:
    """Return True if `payload_size_bytes` fits in the cover.

    Pass the full embed size (e.g. crypto_utils.total_embed_size(payload) or
    len(blob)), not the JSON payload length alone. This is what feeds the
    "is payload size larger than cover object size?" required test case.

    Signature matches image_stego.check_capacity() -- optional start_location
    (default 0) and now low_byte_only, so gui_app.py can call either module
    the same way regardless of file type.
    """
    if payload_size_bytes < 0 or not (1 <= lsb_depth <= 8):
        return False
    params, raw = _load_wav(cover_path)
    usable = _usable_indices(params, low_byte_only)
    # start_location is a raw-byte index; translate it into a position within
    # the usable-index list so capacity math lines up with embed/extract.
    start_offset = sum(1 for idx in usable if idx < start_location)
    return payload_size_bytes <= _bytes_available(len(usable), start_offset, lsb_depth)


# ---------- FR6: embedding ----------

def embed_audio(
    cover_path: str,
    blob: bytes,
    start_location: int,
    lsb_depth: int,
    output_path: str,
    low_byte_only: bool = False,
) -> str:
    """FR6: embed `blob` (already packed by crypto_utils.pack()) into the audio
    cover using LSB replacement, starting at `start_location`.

    `start_location` is a raw-byte index into the frame data (see module
    docstring). Only usable bytes from that point onward are modified -- the
    WAV header and any untouched bytes are left exactly as in the cover.

    low_byte_only=True restricts embedding to the low byte of each sample
    (see _usable_indices docstring) for better audio quality at the cost of
    roughly half the capacity.
    """
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8.")

    params, raw = _load_wav(cover_path)
    usable = _usable_indices(params, low_byte_only)
    cover_size = _cover_size_bytes(params)

    if not (0 <= start_location < cover_size):
        raise ValueError(
            f"start_location {start_location} is outside the audio cover's "
            f"data range (0..{cover_size - 1})"
        )

    start_offset = next((k for k, idx in enumerate(usable) if idx >= start_location), len(usable))
    available_bits = (len(usable) - start_offset) * lsb_depth
    required_bits = len(blob) * 8
    if required_bits > available_bits:
        raise PayloadTooLargeError(
            f"Blob ({len(blob)} bytes) exceeds capacity from "
            f"start_location={start_location}, lsb_depth={lsb_depth}, "
            f"low_byte_only={low_byte_only}."
        )

    bits = _bytes_to_bits(blob)
    mask = (0xFF << lsb_depth) & 0xFF  # clears the low lsb_depth bits, keeps the rest

    bit_idx = 0
    total_bits = len(bits)
    for pos in range(start_offset, len(usable)):
        if bit_idx >= total_bits:
            break
        i = usable[pos]
        chunk = bits[bit_idx:bit_idx + lsb_depth].ljust(lsb_depth, "0")
        raw[i] = (raw[i] & mask) | int(chunk, 2)
        bit_idx += lsb_depth

    _write_wav(output_path, params, raw)
    return str(output_path)


# ---------- FR8: extraction ----------

def extract_audio(
    stego_path: str,
    start_location: int,
    lsb_depth: int,
    low_byte_only: bool = False,
) -> bytes:
    """FR8: reverse of embed_audio(). Returns the raw blob bytes (payload +
    signature, still packed) for crypto_utils.unpack() to consume.

    Two-pass read: decode the 4-byte length header first, then read exactly
    the resulting total blob size. Raises ExtractionError (not a bare
    exception) on anything that looks like a wrong start_location, wrong
    lsb_depth/low_byte_only, or a truncated/corrupted file -- verdict.py
    should catch this and map it to "Wrong Start Location", "Payload Missing"
    or "Cannot Verify" as appropriate.
    """
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8.")

    params, raw = _load_wav(stego_path)
    usable = _usable_indices(params, low_byte_only)
    cover_size = _cover_size_bytes(params)

    if not (0 <= start_location < cover_size):
        raise ExtractionError(
            f"start_location {start_location} is outside the audio cover's "
            f"data range (0..{cover_size - 1})"
        )

    start_offset = next((k for k, idx in enumerate(usable) if idx >= start_location), len(usable))
    max_bytes_from_here = ((len(usable) - start_offset) * lsb_depth) // 8

    def _extract_n_bytes(n_bytes: int) -> bytes:
        needed_bits = n_bytes * 8
        chunks = []
        collected = 0
        pos = start_offset
        while collected < needed_bits:
            if pos >= len(usable):
                raise ExtractionError(
                    "Ran out of audio data before extracting the full blob -- "
                    "likely wrong start_location, lsb_depth, or low_byte_only, "
                    "or a corrupted/tampered file"
                )
            i = usable[pos]
            val = raw[i] & ((1 << lsb_depth) - 1)
            chunks.append(format(val, f"0{lsb_depth}b"))
            collected += lsb_depth
            pos += 1
        return _bits_to_bytes("".join(chunks)[:needed_bits])

    if max_bytes_from_here < LENGTH_HEADER_SIZE:
        raise ExtractionError("Cover too small to contain the length header.")

    header_bytes = _extract_n_bytes(LENGTH_HEADER_SIZE)
    (payload_len,) = _LENGTH_STRUCT.unpack(header_bytes)
    total_blob_len = LENGTH_HEADER_SIZE + payload_len + SIGNATURE_LEN

    if total_blob_len <= 0 or total_blob_len > max_bytes_from_here:
        raise ExtractionError(
            f"Decoded an implausible blob length ({total_blob_len} bytes) -- "
            f"almost certainly the wrong start_location, lsb_depth, or low_byte_only"
        )

    return _extract_n_bytes(total_blob_len)


# ---------- negative test-case helper ----------

def make_tampered_audio(
    stego_path: str,
    output_path: str,
    start_location: int = 0,
    lsb_depth: int = 1,
    low_byte_only: bool = False,
) -> str:
    """Create a negative-case sample: flip one bit inside the embedded blob body.

    Mirrors image_stego.make_tampered_image(). Does not verify signatures --
    Person5/Person4 handle Extract -> Verify -> Verdict. Person6 can call this
    from the GUI to generate FR11 negative evidence for the audio workflow.
    """
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8.")

    params, raw = _load_wav(stego_path)
    usable = _usable_indices(params, low_byte_only)

    start_offset = next((k for k, idx in enumerate(usable) if idx >= start_location), len(usable))
    header_positions = (LENGTH_HEADER_SIZE * 8 + lsb_depth - 1) // lsb_depth
    body_pos = start_offset + header_positions + 8  # a few bytes into the payload body

    if body_pos >= len(usable):
        body_pos = len(usable) - 1  # fall back to the last usable byte

    i = usable[body_pos]
    raw[i] ^= 1  # flip the actual least significant bit -- always inside the
                 # embedded region for any lsb_depth >= 1

    _write_wav(output_path, params, raw)
    return str(output_path)


# ---------- self-test ----------

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


def _run_positive_selftest(*, start_location: int = 500, lsb_depth: int = 2) -> None:
    """Protect cover -> extract blob -> verify signature (smoke for Person2+5)."""
    from crypto_utils import (
        build_payload, compute_hash, load_private_key, load_public_key,
        pack, sign_payload, total_embed_size, unpack, verify_signature,
    )

    root = _repo_root()
    samples = root / "samples"
    cover = samples / "cover_audio.wav"
    stego = samples / "stego_audio_short.wav"

    if not cover.is_file():
        print(f"Missing {cover} -- place a WAV cover there first.")
        sys.exit(1)

    _ensure_keys(root)
    priv = load_private_key(str(root / "keys" / "private_key.pem"))
    pub = load_public_key(str(root / "keys" / "public_key.pem"))

    cover_hash = compute_hash(cover.read_bytes())
    payload = build_payload(
        "AUD-0001", "audio", cover_hash,
        "ACW1 audio stego self-test - Person2 FR6/FR8.",
        metadata={"team": "P1-4", "lsb_depth": lsb_depth},
    )
    signature = sign_payload(payload, priv)
    blob = pack(payload, signature)

    print("FR2 - Audio input")
    print(f"  cover: {cover}")
    print(f"  blob_len: {len(blob)} (4 + payload + 256 sig)")

    fits = check_capacity(str(cover), total_embed_size(payload), lsb_depth, start_location)
    print(f"\nCapacity check: start_location={start_location}, lsb_depth={lsb_depth}, fits={fits}")
    if not fits:
        print("FAIL: payload too large")
        sys.exit(1)

    embed_audio(str(cover), blob, start_location, lsb_depth, str(stego))
    print(f"\nFR6 - Embedded packed blob -> {stego}")

    recovered_blob = extract_audio(str(stego), start_location, lsb_depth)
    recovered_payload, recovered_sig = unpack(recovered_blob)
    ok = verify_signature(recovered_payload, recovered_sig, pub)

    print("\nFR8 - Extracted full blob + crypto verify")
    print(f"  blob_match: {recovered_blob == blob}")
    print(f"  signature_valid: {ok}")

    if recovered_blob != blob or not ok:
        print("\nFAIL: round-trip or signature")
        sys.exit(1)
    print("\nPASS: audio embed/extract + signature OK")


def _run_tamper_only(*, start_location: int = 500, lsb_depth: int = 2) -> None:
    root = _repo_root()
    stego = root / "samples" / "stego_audio_short.wav"
    tampered = root / "samples" / "stego_audio_tampered.wav"
    if not stego.is_file():
        print(f"Missing {stego}\nRun first: python src/audio_stego.py")
        sys.exit(1)
    path = make_tampered_audio(str(stego), str(tampered), start_location=start_location, lsb_depth=lsb_depth)
    print(f"Generated negative sample (tamper only)\n  output: {path}")
    print("Hand to Person5/Person4 for Extract -> Verify -> Verdict.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Person2 audio_stego self-test")
    parser.add_argument("--tamper", action="store_true", help="Only write stego_audio_tampered.wav from existing stego")
    parser.add_argument("--start", type=int, default=500, help="start_location")
    parser.add_argument("--lsb", type=int, default=2, help="lsb_depth 1-8")
    args = parser.parse_args()
    if args.tamper:
        _run_tamper_only(start_location=args.start, lsb_depth=args.lsb)
    else:
        _run_positive_selftest(start_location=args.start, lsb_depth=args.lsb)
