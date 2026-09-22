"""
video_stego.py -- Optional video cover (selected-frame / full-frame LSB)

Team API (mirrors image_stego / audio_stego):
  check_capacity, embed_video, extract_video, make_tampered_video

Method: flatten RGB samples across video frames (row-major per frame, frames in
order) and apply the same LSB replacement used for images. The packed blob is
opaque bytes from crypto_utils.pack():
  [4-byte big-endian N][N JSON payload bytes][256-byte RSA signature]

Indexing: flat R,G,B sample index across all used frames.
  cover_size = n_used_frames * height * width * 3

Codec note: stego is written as lossless AVI (FFV1 when available, else
uncompressed DIB). Lossy MP4/H.264 as *output* would destroy LSBs -- we refuse
to write those as stego. Input may be any OpenCV-readable video; frames are
decoded then re-encoded losslessly.

Self-test from repo root:
  python src/video_stego.py
  python src/video_stego.py --tamper
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import cv2
import numpy as np

SIGNATURE_LEN = 256
LENGTH_HEADER_SIZE = 4
_LENGTH_STRUCT = struct.Struct(">I")


class VideoStegoError(Exception):
    """Base error for video steganography."""


class InvalidVideoError(VideoStegoError):
    """Video could not be loaded or is unsupported."""


class PayloadTooLargeError(VideoStegoError):
    """Blob exceeds cover capacity from start location and LSB depth."""


class ExtractionError(VideoStegoError):
    """Hidden blob could not be read."""


def _open_capture(path: str | Path) -> cv2.VideoCapture:
    path = Path(path)
    if not path.is_file():
        raise InvalidVideoError(f"File not found: {path}")
    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        raise InvalidVideoError(f"Cannot open video: {path}")
    return cap


def _read_all_frames(path: str | Path) -> tuple[list[np.ndarray], float]:
    """Return (list of BGR uint8 frames, fps)."""
    cap = _open_capture(path)
    fps = float(cap.get(cv2.CAP_PROP_FPS) or 24.0)
    frames: list[np.ndarray] = []
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            if frame is None or frame.ndim != 3 or frame.shape[2] < 3:
                raise InvalidVideoError("Video frames must be colour (BGR/RGB).")
            frames.append(frame[:, :, :3].copy())
    finally:
        cap.release()
    if not frames:
        raise InvalidVideoError(f"No frames decoded from: {path}")
    return frames, fps


def _frame_indices(n_frames: int, frame_step: int) -> list[int]:
    if frame_step < 1:
        raise ValueError("frame_step must be >= 1")
    return list(range(0, n_frames, frame_step))


def _flatten_rgb_samples(frames: list[np.ndarray], used_indices: list[int]) -> list[int]:
    """Flat R,G,B samples from selected frames (BGR OpenCV -> R,G,B order)."""
    flat: list[int] = []
    for i in used_indices:
        # OpenCV is BGR; match image_stego channel order R,G,B
        rgb = frames[i][:, :, ::-1]
        flat.extend(int(v) for v in rgb.reshape(-1))
    return flat


def _apply_samples_to_frames(
    frames: list[np.ndarray],
    used_indices: list[int],
    samples: list[int],
) -> list[np.ndarray]:
    """Write flat R,G,B samples back into selected frames (in-place copies)."""
    out = [f.copy() for f in frames]
    offset = 0
    for i in used_indices:
        h, w, _ = out[i].shape
        n = h * w * 3
        chunk = samples[offset:offset + n]
        if len(chunk) != n:
            raise VideoStegoError("Sample count does not match frame geometry.")
        rgb = np.asarray(chunk, dtype=np.uint8).reshape(h, w, 3)
        out[i][:, :, :] = rgb[:, :, ::-1]  # RGB -> BGR
        offset += n
    return out


def _write_video(path: str | Path, frames: list[np.ndarray], fps: float) -> None:
    """Write frames with a lossless-friendly codec (LSB-safe)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() not in (".avi",):
        path = path.with_suffix(".avi")
    h, w = frames[0].shape[:2]
    # Prefer true lossless. Never fall back to MJPG/H.264 -- they destroy LSBs.
    for name in ("FFV1", "DIB ", "RGBA", "raw ", "NONE"):
        fourcc = cv2.VideoWriter_fourcc(*name)
        writer = cv2.VideoWriter(str(path), fourcc, fps if fps > 0 else 24.0, (w, h))
        if not writer.isOpened():
            writer.release()
            continue
        for frame in frames:
            writer.write(frame)
        writer.release()
        if path.is_file() and path.stat().st_size > 0:
            return
    raise InvalidVideoError(
        f"Could not open a lossless VideoWriter for {path}. "
        "Install OpenCV with FFV1 support, or use a platform that supports uncompressed AVI."
    )


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
        for b in range(lsb_depth):
            if bit_idx < total_bits:
                chunk |= bits[bit_idx] << b
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


def video_cover_size(path: str, frame_step: int = 1) -> int:
    """Addressable sample count for Person3 start-location sizing."""
    frames, _ = _read_all_frames(path)
    used = _frame_indices(len(frames), frame_step)
    h, w = frames[0].shape[:2]
    return len(used) * h * w * 3


def check_capacity(
    cover_path: str,
    payload_size_bytes: int,
    lsb_depth: int,
    start_location: int = 0,
    frame_step: int = 1,
) -> bool:
    """Return True if payload_size_bytes fit (pass full blob size / total_embed_size)."""
    if payload_size_bytes < 0:
        return False
    frames, _ = _read_all_frames(cover_path)
    used = _frame_indices(len(frames), frame_step)
    h, w = frames[0].shape[:2]
    sample_count = len(used) * h * w * 3
    return payload_size_bytes <= _bytes_available(sample_count, start_location, lsb_depth)


def embed_video(
    cover_path: str,
    blob: bytes,
    start_location: int,
    lsb_depth: int,
    output_path: str,
    frame_step: int = 1,
) -> str:
    """Embed packed blob into video frame RGB LSBs. Writes lossless AVI."""
    frames, fps = _read_all_frames(cover_path)
    used = _frame_indices(len(frames), frame_step)
    samples = _flatten_rgb_samples(frames, used)

    if not check_capacity(cover_path, len(blob), lsb_depth, start_location, frame_step):
        raise PayloadTooLargeError(
            f"Blob ({len(blob)} bytes) exceeds capacity from "
            f"start_location={start_location}, lsb_depth={lsb_depth}, frame_step={frame_step}."
        )

    stego_samples = _embed_bytes(
        samples, blob, start_location=start_location, lsb_depth=lsb_depth
    )
    stego_frames = _apply_samples_to_frames(frames, used, stego_samples)
    out = Path(output_path).with_suffix(".avi")
    _write_video(out, stego_frames, fps)
    return str(out)


def extract_video(
    stego_path: str,
    start_location: int,
    lsb_depth: int,
    frame_step: int = 1,
) -> bytes:
    """Extract full packed blob [4|payload|signature] for crypto_utils.unpack()."""
    frames, _ = _read_all_frames(stego_path)
    used = _frame_indices(len(frames), frame_step)
    samples = _flatten_rgb_samples(frames, used)
    available = _bytes_available(len(samples), start_location, lsb_depth)
    if available < LENGTH_HEADER_SIZE:
        raise ExtractionError("Cover too small to contain length header.")

    header = _extract_bytes(
        samples, LENGTH_HEADER_SIZE, start_location=start_location, lsb_depth=lsb_depth
    )
    (payload_len,) = _LENGTH_STRUCT.unpack(header)
    total = LENGTH_HEADER_SIZE + payload_len + SIGNATURE_LEN
    if total > available:
        raise ExtractionError(
            f"Declared blob size ({total} bytes) exceeds cover capacity ({available})."
        )
    return _extract_bytes(
        samples, total, start_location=start_location, lsb_depth=lsb_depth
    )


def make_tampered_video(
    stego_path: str,
    output_path: str,
    start_location: int = 0,
    lsb_depth: int = 1,
    frame_step: int = 1,
) -> str:
    """Negative sample: flip one RGB channel inside the embedded blob body."""
    if lsb_depth < 1 or lsb_depth > 8:
        raise ValueError("lsb_depth must be between 1 and 8.")

    frames, fps = _read_all_frames(stego_path)
    used = _frame_indices(len(frames), frame_step)
    samples = _flatten_rgb_samples(frames, used)

    header_samples = (32 + lsb_depth - 1) // lsb_depth
    body_sample = start_location + header_samples + 8
    if body_sample >= len(samples):
        body_sample = max(0, len(samples) - 1)
    samples[body_sample] ^= 1

    stego_frames = _apply_samples_to_frames(frames, used, samples)
    out = Path(output_path).with_suffix(".avi")
    _write_video(out, stego_frames, fps)
    return str(out)


def first_frame_rgb(path: str | Path) -> "Image.Image":
    """Helper for GUI preview: first frame as a Pillow RGB image."""
    from PIL import Image

    frames, _ = _read_all_frames(path)
    rgb = frames[0][:, :, ::-1]
    return Image.fromarray(rgb)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_sample_cover(path: Path, frames: int = 12, size: int = 96, fps: float = 12.0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    out_frames = []
    for i in range(frames):
        img = np.zeros((size, size, 3), dtype=np.uint8)
        img[:, :, 0] = (i * 20) % 256
        img[:, :, 1] = (i * 40) % 256
        img[:, :, 2] = (i * 60) % 256
        cv2.rectangle(img, (10, 10), (size - 10, size - 10), (255, 255, 255), 2)
        cv2.putText(img, str(i), (size // 3, size // 2), cv2.FONT_HERSHEY_SIMPLEX,
                    1.0, (0, 0, 0), 2)
        out_frames.append(img)
    _write_video(path, out_frames, fps)


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
    start_location: int = 50,
    lsb_depth: int = 2,
    frame_step: int = 1,
) -> None:
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
    cover = samples / "cover_video.avi"
    stego = samples / "stego_video_short.avi"

    if not cover.is_file():
        _make_sample_cover(cover)
        print(f"Created sample cover: {cover}")

    _ensure_keys(root)
    priv = load_private_key(str(root / "keys" / "private_key.pem"))
    pub = load_public_key(str(root / "keys" / "public_key.pem"))

    cover_hash = compute_hash(cover.read_bytes())
    payload = build_payload(
        "VID-0001",
        "video",
        cover_hash,
        "ACW1 video stego self-test - optional video cover.",
        metadata={"team": "P1-4", "lsb_depth": lsb_depth, "frame_step": frame_step},
    )
    signature = sign_payload(payload, priv)
    blob = pack(payload, signature)

    print("Video input")
    print(f"  cover: {cover}")
    print(f"  blob_len: {len(blob)} (4 + payload + 256 sig)")
    print(f"  frame_step: {frame_step}")

    fits = check_capacity(
        str(cover), total_embed_size(payload), lsb_depth, start_location, frame_step
    )
    print(f"\nCapacity check: start={start_location}, lsb={lsb_depth}, fits={fits}")
    if not fits:
        print("FAIL: payload too large")
        sys.exit(1)

    embed_video(str(cover), blob, start_location, lsb_depth, str(stego), frame_step)
    print(f"\nEmbedded packed blob -> {stego}")

    recovered = extract_video(str(stego), start_location, lsb_depth, frame_step)
    recovered_payload, recovered_sig = unpack(recovered)
    ok = verify_signature(recovered_payload, recovered_sig, pub)
    print("\nExtracted full blob + crypto verify")
    print(f"  blob_match: {recovered == blob}")
    print(f"  signature_valid: {ok}")
    if recovered != blob or not ok:
        print("\nFAIL: round-trip or signature")
        sys.exit(1)
    print("\nPASS: video embed/extract + signature OK")


def _run_tamper_only(
    *,
    start_location: int = 50,
    lsb_depth: int = 2,
    frame_step: int = 1,
) -> None:
    root = _repo_root()
    stego = root / "samples" / "stego_video_short.avi"
    tampered = root / "samples" / "stego_video_tampered.avi"
    if not stego.is_file():
        print(f"Missing {stego}\nRun first: python src/video_stego.py")
        sys.exit(1)
    path = make_tampered_video(
        str(stego),
        str(tampered),
        start_location=start_location,
        lsb_depth=lsb_depth,
        frame_step=frame_step,
    )
    print(f"Generated negative sample (tamper only)\n  output: {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Optional video_stego self-test")
    parser.add_argument("--tamper", action="store_true")
    parser.add_argument("--start", type=int, default=50)
    parser.add_argument("--lsb", type=int, default=2)
    parser.add_argument("--frame-step", type=int, default=1,
                        help="1=all frames; 2=every 2nd frame (selected-frame mode)")
    args = parser.parse_args()
    if args.tamper:
        _run_tamper_only(
            start_location=args.start, lsb_depth=args.lsb, frame_step=args.frame_step
        )
    else:
        _run_positive_selftest(
            start_location=args.start, lsb_depth=args.lsb, frame_step=args.frame_step
        )
