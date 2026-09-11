"""
image_stego.py -- Person1's module (FR1 image input, FR5 image embedding, FR8 image extraction)

Depends on:
- crypto_utils.pack() / unpack() for the byte blob format (see ALIGNMENT.md Section 4)
- start_location.derive_start_location() for where to begin embedding

Hands off to:
- gui_app.py calls embed_image() / extract_image()
- verdict.py consumes what extract_image() returns
"""

from PIL import Image


def check_capacity(cover_path: str, payload_size_bytes: int, lsb_depth: int) -> bool:
    """Mandatory scope item: reject if the payload won't fit in the cover.

    TODO: open the image, compute width * height * channels * lsb_depth bits
    available, compare against payload_size_bytes * 8. Return True if it fits.
    """
    raise NotImplementedError


def embed_image(cover_path: str, blob: bytes, start_location: int, lsb_depth: int, output_path: str) -> str:
    """FR5: embed `blob` (already packed by crypto_utils.pack()) into the cover
    image using LSB replacement -- overwrite the lowest `lsb_depth` bits of each
    channel value, starting at `start_location`. Agree the exact indexing scheme
    (flat pixel index? pixel+channel index?) with Person3 before building this.
    Must always save as PNG regardless of input format (JPEG compression would
    destroy the hidden bits).

    TODO: implement.
    Returns: path to the saved stego PNG.
    """
    raise NotImplementedError


def extract_image(stego_path: str, start_location: int, lsb_depth: int) -> bytes:
    """FR8: reverse of embed_image() -- read lsb_depth bits per channel starting at
    start_location, reassemble into a byte blob to hand to crypto_utils.unpack().

    TODO: implement.
    Returns: the raw blob bytes (payload + signature, still packed).
    """
    raise NotImplementedError
