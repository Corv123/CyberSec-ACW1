"""
start_location.py -- Person3's module (FR7 variable start location, FR13 innovation)

Both image_stego.py and audio_stego.py call derive_start_location() so the encoder
and decoder always agree on where embedding began, without hardcoding it.

Suggested innovation angle (confirm with team -- see ALIGNMENT.md open decisions):
derive the location from a keyed PRNG rather than a fixed or plainly-stored value,
so it can't be guessed without the key/seed.
"""


def derive_start_location(cover_size: int, seed: bytes) -> int:
    """Given the cover's total addressable size (pixels*channels for images,
    samples for audio) and a shared seed, deterministically produce a start index.
    Same seed + same cover_size must always produce the same location -- that's what
    lets the decoder find it again without the location being sent in the clear.

    TODO: implement -- e.g. hash the seed with the cover_size and take it mod
    cover_size, or something stronger for the innovation writeup (keyed PRNG,
    encrypted header, etc.). Coordinate the seed source with Person5 -- reuse the
    shared keypair, or a separate shared secret?

    Returns: an integer index into the cover's flat data array.
    """
    raise NotImplementedError


def explain_security() -> str:
    """TODO: fill in -- a short explanation (for the innovation write-up and the
    live demo Q&A) of why this scheme resists guessing/brute-force, and what its
    limitations are."""
    raise NotImplementedError
