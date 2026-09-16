"""
audio_stego.py -- Person2's module (FR2 audio input, FR6 audio embedding, FR8 audio extraction)

Same shape as image_stego.py, applied to WAV/PCM samples (a flat 1D array) instead
of pixels. Depends on / hands off to the same modules -- see ALIGNMENT.md Section 5.

Start-location scheme (confirm with Person3):
    `start_location` is a flat BYTE index into the raw frame data returned by
    wave.readframes() -- i.e. every byte of every sample, interleaved across
    channels, in file order. Person3's derive_start_location(cover_size, seed)
    should compute cover_size the same way this module does:
        cover_size = nframes * nchannels * sampwidth

Wire format (from crypto_utils.pack(), see ALIGNMENT.md Section 4):
    [4-byte big-endian length][JSON payload bytes][256-byte RSA-2048 signature]

extract_audio() doesn't know the payload length up front, so it reads in two
passes: first just enough bits to decode the 4-byte length header, then computes
the exact total blob size and reads exactly that many bytes. The length header
embedded in the blob is authoritative -- nothing else needs to store the size.
"""

import struct
import wave

try:
    from crypto_utils import SIGNATURE_LEN
except ImportError:
    # Fallback so this module can still be exercised standalone (e.g. a quick
    # test outside the full repo). Keep in sync with crypto_utils.SIGNATURE_LEN.
    SIGNATURE_LEN = 256  # bytes, fixed for a 2048-bit RSA key

LENGTH_HEADER_SIZE = 4  # bytes, matches struct.pack(">I", ...) in crypto_utils.pack()


# ---------- internal helpers ----------

def _read_wav(path: str):
    """Open a WAV/PCM file and return (params, raw_frame_bytes).

    params is wave's Params namedtuple -- needed to write back an identical
    header (sample rate, channels, sample width, etc.) later. raw_frame_bytes is
    a mutable bytearray of every byte of every sample, in file order.
    """
    with wave.open(path, "rb") as wf:
        params = wf.getparams()
        raw = wf.readframes(params.nframes)
    return params, bytearray(raw)


def _write_wav(path: str, params, raw_bytes: bytearray) -> None:
    """Write raw_bytes out as a WAV file with the exact same header params as
    the original cover. Only sample data changes -- the header is untouched."""
    with wave.open(path, "wb") as wf:
        wf.setparams(params)
        wf.writeframes(bytes(raw_bytes))


def _cover_size_bytes(params) -> int:
    """Total addressable raw sample bytes -- must match how Person3's
    derive_start_location() computes cover_size for audio."""
    return params.nframes * params.nchannels * params.sampwidth


def _bytes_to_bits(data: bytes) -> str:
    return "".join(format(b, "08b") for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    # Caller is expected to pass a length that's an exact multiple of 8.
    out = bytearray()
    for i in range(0, len(bits) - (len(bits) % 8), 8):
        out.append(int(bits[i:i + 8], 2))
    return bytes(out)


# ---------- FR2 + mandatory scope: capacity check ----------

def check_capacity(cover_path: str, payload_size_bytes: int, lsb_depth: int) -> bool:
    """Mandatory scope item: does the payload fit in the cover at this LSB depth?

    `payload_size_bytes` should be the *total blob size* that will actually be
    embedded -- i.e. crypto_utils.total_embed_size(payload), not just the JSON
    payload length. This is what feeds the "is payload size larger than cover
    object size?" required test case.
    """
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8")

    with wave.open(cover_path, "rb") as wf:
        params = wf.getparams()

    available_bits = _cover_size_bytes(params) * lsb_depth
    required_bits = payload_size_bytes * 8
    return available_bits >= required_bits


# ---------- FR6: embedding ----------

def embed_audio(cover_path: str, blob: bytes, start_location: int, lsb_depth: int, output_path: str) -> str:
    """FR6: embed `blob` (already packed by crypto_utils.pack()) into the audio
    cover using LSB replacement, starting at `start_location`.

    Only sample bytes from start_location onward are modified -- the WAV header
    and any bytes outside that range are left untouched.
    """
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8")

    params, raw = _read_wav(cover_path)
    cover_size = _cover_size_bytes(params)

    if not (0 <= start_location < cover_size):
        raise ValueError(
            f"start_location {start_location} is outside the audio cover's "
            f"data range (0..{cover_size - 1})"
        )

    required_bits = len(blob) * 8
    available_bits = (cover_size - start_location) * lsb_depth
    if required_bits > available_bits:
        raise ValueError(
            f"Payload does not fit from start_location {start_location} onward: "
            f"need {required_bits} bits, only {available_bits} available"
        )

    bits = _bytes_to_bits(blob)
    mask = (0xFF << lsb_depth) & 0xFF  # clears the low lsb_depth bits, keeps the rest

    i = start_location
    bit_idx = 0
    total_bits = len(bits)
    while bit_idx < total_bits:
        chunk = bits[bit_idx:bit_idx + lsb_depth].ljust(lsb_depth, "0")
        raw[i] = (raw[i] & mask) | int(chunk, 2)
        bit_idx += lsb_depth
        i += 1

    _write_wav(output_path, params, raw)
    return output_path


# ---------- FR8: extraction ----------

def extract_audio(stego_path: str, start_location: int, lsb_depth: int) -> bytes:
    """FR8: reverse of embed_audio(). Returns the raw blob bytes (payload +
    signature, still packed) for crypto_utils.unpack() to consume.

    Raises ValueError on anything that looks like a wrong start_location, wrong
    lsb_depth, or a truncated/corrupted file -- verdict.py should catch this and
    map it to "Wrong Start Location", "Payload Missing" or "Cannot Verify" as
    appropriate rather than letting the exception propagate to the GUI.
    """
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8")

    params, raw = _read_wav(stego_path)
    cover_size = _cover_size_bytes(params)

    if not (0 <= start_location < cover_size):
        raise ValueError(
            f"start_location {start_location} is outside the audio cover's "
            f"data range (0..{cover_size - 1})"
        )

    def _extract_n_bytes(n_bytes: int) -> bytes:
        needed_bits = n_bytes * 8
        chunks = []
        i = start_location
        collected = 0
        while collected < needed_bits:
            if i >= cover_size:
                raise ValueError(
                    "Ran out of audio data before extracting the full blob -- "
                    "likely wrong start_location, wrong lsb_depth, or a "
                    "corrupted/tampered file"
                )
            val = raw[i] & ((1 << lsb_depth) - 1)
            chunks.append(format(val, f"0{lsb_depth}b"))
            collected += lsb_depth
            i += 1
        return _bits_to_bytes("".join(chunks)[:needed_bits])

    # Pass 1: read just the 4-byte length header to find out how big the blob is.
    header_bytes = _extract_n_bytes(LENGTH_HEADER_SIZE)
    payload_len = struct.unpack(">I", header_bytes)[0]

    total_blob_len = LENGTH_HEADER_SIZE + payload_len + SIGNATURE_LEN

    # Sanity check: a wrong start_location/lsb_depth usually decodes into a
    # nonsense (huge) payload_len. Fail fast with a clear error rather than
    # trying to extract gigabytes of bits from a small file.
    max_possible = cover_size - start_location
    if total_blob_len <= 0 or total_blob_len > max_possible:
        raise ValueError(
            f"Decoded an implausible blob length ({total_blob_len} bytes) -- "
            f"almost certainly the wrong start_location or lsb_depth"
        )

    # Pass 2: now that the exact size is known, read the full blob in one go.
    return _extract_n_bytes(total_blob_len)


# ---------- self-test ----------

if __name__ == "__main__":
    import os
    import struct as _struct

    # Build a tiny synthetic WAV cover (1 sec of silence, mono, 16-bit, 8kHz)
    # purely so this file can be sanity-checked without a real audio sample.
    test_cover = "test_cover.wav"
    with wave.open(test_cover, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(b"\x00\x00" * 8000)

    # Fake a blob in the exact crypto_utils.pack() shape without importing it,
    # so this self-test has no external dependency.
    fake_payload = b'{"message":"hello world"}'
    fake_signature = bytes(SIGNATURE_LEN)  # dummy signature, just for shape
    fake_blob = _struct.pack(">I", len(fake_payload)) + fake_payload + fake_signature

    assert check_capacity(test_cover, len(fake_blob), lsb_depth=1), "Should fit easily"

    stego_path = embed_audio(test_cover, fake_blob, start_location=100, lsb_depth=2, output_path="test_stego.wav")
    recovered_blob = extract_audio(stego_path, start_location=100, lsb_depth=2)

    print("Blob round-trip matches:", recovered_blob == fake_blob)

    os.remove(test_cover)
    os.remove(stego_path)
