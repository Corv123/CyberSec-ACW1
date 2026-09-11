"""
audio_stego.py -- Person2's module (FR2 audio input, FR6 audio embedding, FR8 audio extraction)

Same shape as image_stego.py, applied to WAV/PCM samples (a flat 1D array) instead
of pixels. Depends on / hands off to the same modules -- see ALIGNMENT.md Section 5.
"""

import wave


def check_capacity(cover_path: str, payload_size_bytes: int, lsb_depth: int) -> bool:
    """TODO: open the WAV file, compute n_frames * n_channels * lsb_depth bits
    available, compare against payload_size_bytes * 8."""
    raise NotImplementedError


def embed_audio(cover_path: str, blob: bytes, start_location: int, lsb_depth: int, output_path: str) -> str:
    """FR6: embed `blob` into audio sample data using LSB replacement, starting at
    start_location (a flat sample index -- agree the exact scheme with Person3).
    Preserve the WAV header exactly; only modify sample bytes.

    TODO: implement.
    Returns: path to the saved stego WAV.
    """
    raise NotImplementedError


def extract_audio(stego_path: str, start_location: int, lsb_depth: int) -> bytes:
    """FR8: reverse of embed_audio().

    TODO: implement.
    Returns: the raw blob bytes (payload + signature, still packed).
    """
    raise NotImplementedError
