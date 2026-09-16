"""
verdict.py -- Person4's module (FR10 verdict generation, FR13 innovation)

Consumes:
- crypto_utils.verify_signature() / verify_hash() results
- whether image_stego / audio_stego extraction succeeded at the expected location

Produces one of the six verdicts required by the spec (Section 7 / FR10).
"""

VERDICTS = [
    "Authentic",
    "Tampered",
    "Signature Invalid",
    "Payload Missing",
    "Wrong Start Location",
    "Cannot Verify",
]


def generate_verdict(extraction_successful: bool, signature_valid: bool, hash_valid: bool) -> str:
    """TODO: implement the decision logic -- this rough shape is a starting point,
    replace it with your own reasoning and edge cases:

      - extraction failed entirely      -> "Payload Missing" or "Wrong Start Location"
      - extraction ok, signature invalid -> "Signature Invalid"
      - signature ok, hash mismatch      -> "Tampered"
      - both valid                       -> "Authentic"
      - anything unexpected / exception  -> "Cannot Verify"
    """
    raise NotImplementedError


def run_attack_simulation():
    """Suggested innovation (confirm with team -- see ALIGNMENT.md open decisions):
    a test harness that runs through the negative cases automatically -- wrong key,
    corrupted payload, wrong start location, replayed nonce -- and reports pass/fail
    for each. Feeds directly into the FR11 negative-case requirement too.

    TODO: implement.
    """
    raise NotImplementedError
