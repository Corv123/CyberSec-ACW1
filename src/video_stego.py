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

Performance: NumPy LSB ops; capacity/size from container metadata (no full decode);
extract decodes only frames that hold the payload; embed touches only the sample
slice that carries the blob (full frame list still written once for lossless AVI).

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


def _read_first_frame(path: str | Path) -> tuple[np.ndarray, float]:
    """Decode only the first colour frame (GUI preview / geometry)."""
    cap = _open_capture(path)
    fps = float(cap.get(cv2.CAP_PROP_FPS) or 24.0)
    try:
        ok, frame = cap.read()
        if not ok or frame is None or frame.ndim != 3 or frame.shape[2] < 3:
            raise InvalidVideoError(f"No colour frames in: {path}")
        return frame[:, :, :3].copy(), fps
    finally:
        cap.release()


def _probe_geometry(path: str | Path) -> tuple[int, int, int, float]:
    """Return (n_frames, height, width, fps) without decoding every frame.

    Uses container metadata when reliable; otherwise counts by reading once.
    """
    cap = _open_capture(path)
    try:
        fps = float(cap.get(cv2.CAP_PROP_FPS) or 24.0)
        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        n_meta = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    finally:
        cap.release()

    if w > 0 and h > 0 and n_meta > 0:
        return n_meta, h, w, fps

    frames, fps = _read_all_frames(path)
    h, w = frames[0].shape[:2]
    return len(frames), h, w, fps


def _frame_indices(n_frames: int, frame_step: int) -> list[int]:
    if frame_step < 1:
        raise ValueError("frame_step must be >= 1")
    return list(range(0, n_frames, frame_step))


def _per_frame_samples(h: int, w: int) -> int:
    return h * w * 3


def _samples_for_bytes(byte_count: int, lsb_depth: int) -> int:
    return (byte_count * 8 + lsb_depth - 1) // lsb_depth


def _flatten_rgb_samples(frames: list[np.ndarray], used_indices: list[int]) -> np.ndarray:
    """Flat R,G,B uint8 samples from selected frames (BGR OpenCV -> R,G,B order)."""
    if not used_indices:
        return np.empty(0, dtype=np.uint8)
    planes = [np.ascontiguousarray(frames[i][:, :, ::-1]).ravel() for i in used_indices]
    return np.concatenate(planes)


def _gather_sample_slice(
    frames: list[np.ndarray],
    used_indices: list[int],
    start: int,
    count: int,
) -> np.ndarray:
    """Copy samples[start:start+count] without building the full flat cover."""
    if count <= 0:
        return np.empty(0, dtype=np.uint8)
    h, w = frames[used_indices[0]].shape[:2]
    ppc = _per_frame_samples(h, w)
    out = np.empty(count, dtype=np.uint8)
    out_off = 0
    end = start + count
    first_used = start // ppc
    last_used = (end - 1) // ppc
    for ui in range(first_used, last_used + 1):
        if ui >= len(used_indices):
            break
        plane = np.ascontiguousarray(frames[used_indices[ui]][:, :, ::-1]).ravel()
        lo = ui * ppc
        hi = lo + ppc
        a = max(start, lo)
        b = min(end, hi)
        if a < b:
            take = plane[a - lo:b - lo]
            out[out_off:out_off + len(take)] = take
            out_off += len(take)
    if out_off != count:
        raise VideoStegoError(
            f"Gathered {out_off} samples but needed {count} "
            f"(start={start}, used_frames={len(used_indices)})."
        )
    return out


def _scatter_sample_slice(
    frames: list[np.ndarray],
    used_indices: list[int],
    start: int,
    region: np.ndarray,
) -> None:
    """Write a flat RGB sample slice back into BGR frames (in-place)."""
    if region.size == 0:
        return
    h, w = frames[used_indices[0]].shape[:2]
    ppc = _per_frame_samples(h, w)
    end = start + int(region.size)
    first_used = start // ppc
    last_used = (end - 1) // ppc
    src_off = 0
    for ui in range(first_used, last_used + 1):
        if ui >= len(used_indices):
            break
        fi = used_indices[ui]
        plane = np.ascontiguousarray(frames[fi][:, :, ::-1]).ravel().copy()
        lo = ui * ppc
        hi = lo + ppc
        a = max(start, lo)
        b = min(end, hi)
        if a < b:
            n = b - a
            plane[a - lo:b - lo] = region[src_off:src_off + n]
            src_off += n
            frames[fi][:, :, :] = plane.reshape(h, w, 3)[:, :, ::-1]


def _apply_samples_to_frames(
    frames: list[np.ndarray],
    used_indices: list[int],
    samples: np.ndarray | list[int],
) -> list[np.ndarray]:
    """Write full flat R,G,B samples back into selected frames."""
    arr = np.asarray(samples, dtype=np.uint8)
    out = [f.copy() for f in frames]
    _scatter_sample_slice(out, used_indices, 0, arr)
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


def _embed_into_array(
    samples: np.ndarray,
    data: bytes,
    *,
    start_location: int,
    lsb_depth: int,
) -> None:
    """In-place NumPy LSB embed into a uint8 sample array (same bit order as image_stego)."""
    if lsb_depth < 1 or lsb_depth > 8:
        raise ValueError("lsb_depth must be between 1 and 8.")
    if start_location < 0 or start_location >= len(samples):
        raise ValueError("start_location out of range.")

    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="big")
    n_bits = int(bits.size)
    n_samples = _samples_for_bytes(len(data), lsb_depth)
    if start_location + n_samples > len(samples):
        raise PayloadTooLargeError(
            f"Need {n_bits} bits but cover only has room for "
            f"{(len(samples) - start_location) * lsb_depth} from start_location={start_location}."
        )

    padded = np.zeros(n_samples * lsb_depth, dtype=np.uint8)
    padded[:n_bits] = bits
    # First bitstream bit -> LSB of the sample chunk (matches prior Python loop).
    chunk = np.zeros(n_samples, dtype=np.uint16)
    for b in range(lsb_depth):
        chunk |= padded[b::lsb_depth].astype(np.uint16) << b
    chunk = chunk.astype(np.uint8)

    clear_mask = np.uint8((~((1 << lsb_depth) - 1)) & 0xFF)
    sl = samples[start_location:start_location + n_samples]
    sl[:] = (sl & clear_mask) | chunk


def _extract_from_array(
    samples: np.ndarray,
    byte_count: int,
    *,
    start_location: int,
    lsb_depth: int,
) -> bytes:
    """NumPy LSB extract; bit order matches image_stego / prior Python loop."""
    if lsb_depth < 1 or lsb_depth > 8:
        raise ValueError("lsb_depth must be between 1 and 8.")
    if byte_count < 0:
        raise ValueError("byte_count must be non-negative.")
    if byte_count == 0:
        return b""

    n_samples = _samples_for_bytes(byte_count, lsb_depth)
    if start_location < 0 or start_location + n_samples > len(samples):
        raise ExtractionError(
            f"Need {byte_count * 8} bits but cover slice is too short "
            f"(start={start_location}, samples={len(samples)})."
        )

    mask = np.uint8((1 << lsb_depth) - 1)
    values = samples[start_location:start_location + n_samples] & mask
    bits = np.empty(n_samples * lsb_depth, dtype=np.uint8)
    for b in range(lsb_depth):
        bits[b::lsb_depth] = (values >> b) & 1
    bits = bits[: byte_count * 8]
    return np.packbits(bits, bitorder="big").tobytes()


# Kept for any external callers / tests that still pass list-like covers.
def _embed_bytes(samples, data: bytes, *, start_location: int, lsb_depth: int):
    arr = np.array(samples, dtype=np.uint8, copy=True)
    _embed_into_array(arr, data, start_location=start_location, lsb_depth=lsb_depth)
    if isinstance(samples, np.ndarray):
        return arr
    return arr.tolist()


def _extract_bytes(samples, byte_count: int, *, start_location: int, lsb_depth: int) -> bytes:
    arr = np.asarray(samples, dtype=np.uint8)
    return _extract_from_array(
        arr, byte_count, start_location=start_location, lsb_depth=lsb_depth
    )


def _read_sample_range(
    path: str | Path,
    frame_step: int,
    start_sample: int,
    count: int,
) -> tuple[np.ndarray, int]:
    """Decode only frames that hold samples[start:start+count].

    Returns (sample_slice, total_cover_sample_count).
    """
    if count < 0:
        raise ValueError("count must be non-negative")
    n_frames, h, w, _fps = _probe_geometry(path)
    used = _frame_indices(n_frames, frame_step)
    ppc = _per_frame_samples(h, w)
    sample_count = len(used) * ppc
    if start_sample < 0 or start_sample > sample_count:
        raise ExtractionError("start_location out of cover range.")
    if start_sample + count > sample_count:
        raise ExtractionError(
            f"Need {count} samples from {start_sample} but cover only has "
            f"{sample_count - start_sample} remaining."
        )
    if count == 0:
        return np.empty(0, dtype=np.uint8), sample_count

    first_used = start_sample // ppc
    last_used = (start_sample + count - 1) // ppc
    first_abs = used[first_used]
    last_abs = used[last_used]

    cap = _open_capture(path)
    planes: list[np.ndarray] = []
    abs_i = 0
    try:
        while abs_i <= last_abs:
            ok, frame = cap.read()
            if not ok:
                break
            if first_abs <= abs_i <= last_abs and abs_i % frame_step == 0:
                if frame is None or frame.ndim != 3 or frame.shape[2] < 3:
                    raise InvalidVideoError("Video frames must be colour (BGR/RGB).")
                planes.append(np.ascontiguousarray(frame[:, :, :3][:, :, ::-1]).ravel())
            abs_i += 1
    finally:
        cap.release()

    if len(planes) != (last_used - first_used + 1):
        # Metadata frame count can be wrong; fall back to full decode for this range.
        frames, _ = _read_all_frames(path)
        used = _frame_indices(len(frames), frame_step)
        return _gather_sample_slice(frames, used, start_sample, count), len(used) * ppc

    stacked = np.concatenate(planes)
    local_start = start_sample - first_used * ppc
    return stacked[local_start:local_start + count].copy(), sample_count


def video_cover_size(path: str, frame_step: int = 1) -> int:
    """Addressable sample count for Person3 start-location sizing."""
    n_frames, h, w, _fps = _probe_geometry(path)
    used = len(_frame_indices(n_frames, frame_step))
    return used * _per_frame_samples(h, w)


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
    sample_count = video_cover_size(cover_path, frame_step)
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
    if lsb_depth < 1 or lsb_depth > 8:
        raise ValueError("lsb_depth must be between 1 and 8.")

    frames, fps = _read_all_frames(cover_path)
    used = _frame_indices(len(frames), frame_step)
    h, w = frames[0].shape[:2]
    sample_count = len(used) * _per_frame_samples(h, w)

    if len(blob) > _bytes_available(sample_count, start_location, lsb_depth):
        raise PayloadTooLargeError(
            f"Blob ({len(blob)} bytes) exceeds capacity from "
            f"start_location={start_location}, lsb_depth={lsb_depth}, frame_step={frame_step}."
        )

    n = _samples_for_bytes(len(blob), lsb_depth)
    region = _gather_sample_slice(frames, used, start_location, n)
    _embed_into_array(region, blob, start_location=0, lsb_depth=lsb_depth)
    _scatter_sample_slice(frames, used, start_location, region)

    out = Path(output_path).with_suffix(".avi")
    _write_video(out, frames, fps)
    return str(out)


def extract_video(
    stego_path: str,
    start_location: int,
    lsb_depth: int,
    frame_step: int = 1,
) -> bytes:
    """Extract full packed blob [4|payload|signature] for crypto_utils.unpack()."""
    if lsb_depth < 1 or lsb_depth > 8:
        raise ValueError("lsb_depth must be between 1 and 8.")

    header_n = _samples_for_bytes(LENGTH_HEADER_SIZE, lsb_depth)
    header_samples, sample_count = _read_sample_range(
        stego_path, frame_step, start_location, header_n
    )
    available = _bytes_available(sample_count, start_location, lsb_depth)
    if available < LENGTH_HEADER_SIZE:
        raise ExtractionError("Cover too small to contain length header.")

    header = _extract_from_array(
        header_samples, LENGTH_HEADER_SIZE, start_location=0, lsb_depth=lsb_depth
    )
    (payload_len,) = _LENGTH_STRUCT.unpack(header)
    total = LENGTH_HEADER_SIZE + payload_len + SIGNATURE_LEN
    if total > available:
        raise ExtractionError(
            f"Declared blob size ({total} bytes) exceeds cover capacity ({available})."
        )

    total_n = _samples_for_bytes(total, lsb_depth)
    if total_n <= header_n:
        body = header_samples[:total_n]
    else:
        body, _ = _read_sample_range(stego_path, frame_step, start_location, total_n)
    return _extract_from_array(body, total, start_location=0, lsb_depth=lsb_depth)


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
    sample_count = len(used) * _per_frame_samples(*frames[0].shape[:2])

    header_samples = (32 + lsb_depth - 1) // lsb_depth
    body_sample = start_location + header_samples + 8
    if body_sample >= sample_count:
        body_sample = max(0, sample_count - 1)

    region = _gather_sample_slice(frames, used, body_sample, 1)
    region[0] ^= 1
    _scatter_sample_slice(frames, used, body_sample, region)

    out = Path(output_path).with_suffix(".avi")
    _write_video(out, frames, fps)
    return str(out)


def first_frame_rgb(path: str | Path) -> "Image.Image":
    """Helper for GUI preview: first frame as a Pillow RGB image."""
    from PIL import Image

    frame, _ = _read_first_frame(path)
    return Image.fromarray(frame[:, :, ::-1])


def iter_stable_rgb_frames(path: str | Path, lsb_depth: int):
    """Yield masked RGB uint8 planes (C-order) for streaming FR9 hashing."""
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8.")
    mask = np.uint8((0xFF << lsb_depth) & 0xFF)
    cap = _open_capture(path)
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            if frame is None or frame.ndim != 3 or frame.shape[2] < 3:
                raise InvalidVideoError("Video frames must be colour (BGR/RGB).")
            rgb = np.ascontiguousarray(frame[:, :, :3][:, :, ::-1])
            yield (rgb & mask)
    finally:
        cap.release()


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
    cover = samples / "cover_video_selftest.avi"
    stego = samples / "stego_video_short.avi"
    # Always use a tiny synthetic cover for self-test (user demos may use a large AVI).
    _make_sample_cover(cover)
    print(f"Self-test cover: {cover}")

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
