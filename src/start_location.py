"""
start_location.py -- Person3's module (FR7 variable start location, FR13 innovation)

Both image_stego.py and audio_stego.py (via gui_pipeline.py) call
derive_secrets() so the encoder and decoder always agree on where embedding
began, without the location ever being transmitted or stored in the clear.

Method (see explain_security() for the full write-up):
  1. Stretch the shared `seed` with PBKDF2-HMAC-SHA256 (many iterations), so
     every seed guess costs an attacker real time.
  2. Use the stretched key as an HMAC-SHA256 keystream (counter mode) and reduce it
     to an index in [0, cover_size) by rejection sampling, so every location is
     exactly equally likely.
  3. Derive a second, independent key from the stretched key and XOR-encrypt the
     whole blob (length header + payload + signature) with its keystream. Without
     this, the plaintext header and JSON let an attacker skip the seed entirely
     and just scan every offset (a few seconds on a 48M-sample image).

Self-test from repo root: `python src/start_location.py`
"""

from __future__ import annotations

import hashlib
import hmac
import math
import struct

# Fixed, non-secret domain-separation string. Combined with cover_size so the same
# seed still stretches differently for differently-sized covers.
_SALT_PREFIX = b"ACW1-start-location-v1"

# PBKDF2 iteration count -- the real defence against a brute-forced seed. Tuned to
# keep a single derive_start_location() call well under a second in the GUI while
# still costing an attacker real time per guess.
PBKDF2_ITERATIONS = 200_000
_STRETCHED_KEY_LEN = 32  # bytes, matches SHA-256 output

# Domain-separation label for the blob-encryption key, so it is independent of the
# keystream that picks the start index.
_MASK_LABEL = b"ACW1-blob-mask-v1"


def _stretch_seed(seed: bytes, cover_size: int) -> bytes:
    """PBKDF2-HMAC-SHA256 key stretching. The salt is not secret (fixed prefix +
    cover_size, purely for domain separation across differently-sized covers) --
    only `seed` needs to stay secret. Deterministic: the same seed + cover_size
    always stretches to the same key.
    """
    salt = _SALT_PREFIX + struct.pack(">Q", cover_size)
    return hashlib.pbkdf2_hmac("sha256", seed, salt, PBKDF2_ITERATIONS, dklen=_STRETCHED_KEY_LEN)


def _keystream_block(key: bytes, counter: int) -> bytes:
    """One 32-byte block of an HMAC-SHA256 counter-mode keystream."""
    return hmac.new(key, struct.pack(">Q", counter), hashlib.sha256).digest()


def _unbiased_index(key: bytes, upper: int) -> int:
    """Rejection sampling: reduces the keystream to an index uniformly distributed
    over [0, upper), with no modulo bias. (Naive `int(...) % upper` over-represents
    the low end whenever `upper` is not a power of two.)
    """
    if upper <= 0:
        raise ValueError("upper must be positive")

    num_bits = max(1, (upper - 1).bit_length())
    num_bytes = (num_bits + 7) // 8
    mask = (1 << num_bits) - 1

    counter = 0
    while True:
        block = b""
        while len(block) < num_bytes:
            block += _keystream_block(key, counter)
            counter += 1
        candidate = int.from_bytes(block[:num_bytes], "big") & mask
        if candidate < upper:
            return candidate
        # else: discard and draw the next block(s) -- expected < 2 attempts.


def _check_inputs(cover_size: int, seed: bytes) -> None:
    if cover_size <= 0:
        raise ValueError("cover_size must be positive")
    if not isinstance(seed, bytes):
        raise TypeError("seed must be bytes")
    if not seed:
        # An empty seed would give a fixed, publicly computable start and key --
        # the first thing an attacker would try.
        raise ValueError("seed must not be empty")


def derive_secrets(cover_size: int, seed: bytes) -> tuple[int, bytes]:
    """One PBKDF2 run -> (start index, blob-encryption key).

    The start index is uniform over [0, cover_size); the key feeds apply_mask().
    Same seed + same cover_size always gives the same pair, so the verifier
    re-computes both instead of reading them from the file.
    """
    _check_inputs(cover_size, seed)
    stretched = _stretch_seed(seed, cover_size)
    start = _unbiased_index(stretched, cover_size)
    mask_key = hmac.new(stretched, _MASK_LABEL, hashlib.sha256).digest()
    return start, mask_key


def apply_mask(data: bytes, mask_key: bytes) -> bytes:
    """XOR `data` with the HMAC-SHA256 counter-mode keystream of `mask_key`,
    starting at keystream offset 0. Its own inverse: apply once to encrypt,
    again to decrypt. Because it always starts at offset 0, decrypting just the
    first 4 bytes gives the same header as decrypting the whole blob.
    """
    n_blocks = (len(data) + 31) // 32
    stream = b"".join(_keystream_block(mask_key, i) for i in range(n_blocks))[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(data), "big")


def derive_start_location(cover_size: int, seed: bytes) -> int:
    """Given the cover's total addressable size (pixels*channels for images,
    samples*sample_width for audio -- see gui_pipeline.py) and a shared seed,
    deterministically produce a start index. Same seed + same cover_size always
    produces the same location -- that's what lets the decoder find it again
    without the location being sent in the clear.

    Returns: an integer index into the cover's flat data array, 0 <= index < cover_size.
    """
    return derive_secrets(cover_size, seed)[0]


def explain_security() -> str:
    """Short explanation for the innovation write-up and live-demo Q&A."""
    return (
        "IMPROVEMENT OVER BASELINE (fixed-location LSB)\n"
        "  Baseline: payload at a known spot, plain text -> read or scanned instantly.\n"
        "  Ours: start + encryption key from the seed -> full offset scan finds nothing.\n"
        "  Nothing stored in the file; each seed guess costs "
        f"{PBKDF2_ITERATIONS:,} PBKDF2 rounds.\n"
        "\n"
        "HOW THE START LOCATION IS CHOSEN\n"
        "  1. Seed (passphrase shared by sender and verifier)\n"
        f"     -> PBKDF2-HMAC-SHA256, {PBKDF2_ITERATIONS:,} rounds -> 256-bit key.\n"
        "  2. Key -> HMAC-SHA256 random stream -> start index in [0, cover size),\n"
        "     picked by rejection sampling so every position is equally likely.\n"
        "  3. A second key from the same seed XOR-encrypts the whole hidden blob\n"
        "     (length header + payload + signature).\n"
        "\n"
        "WHAT DOES THE SECURITY WORK (and what doesn't)\n"
        "  - Secret seed + HMAC-SHA256: makes the start unpredictable.\n"
        f"  - PBKDF2 ({PBKDF2_ITERATIONS:,} rounds): makes every seed guess slow.\n"
        "  - Blob encryption: stops the scan-every-offset shortcut.\n"
        "  - Rejection sampling: correctness only. It removes modulo bias so every\n"
        "    position is exactly equally likely, but adds no unpredictability and\n"
        "    no security on its own.\n"
        "\n"
        "HOW THE VERIFIER FINDS IT\n"
        "  Nothing about the location is stored in the file. The verifier enters\n"
        "  the same seed, reads the cover size from the file, and re-runs steps\n"
        "  1-3 to get the same start and key.\n"
        "\n"
        "WHY THE ENCRYPTION MATTERS\n"
        "  A hidden start on its own is weak: a cover has only ~2^25 positions,\n"
        "  and a plaintext length header and JSON are easy to spot. Our own test\n"
        "  scanned every offset of an unencrypted stego image and found the\n"
        "  payload in ~3 s without the seed. Once encrypted, every offset looks\n"
        "  like random bits, so the attacker has to guess the seed instead.\n"
        "\n"
        "LIMITATIONS\n"
        "  - Only as strong as the seed. An attacker can still try seeds offline\n"
        "    (derive -> decrypt -> check RSA signature). PBKDF2 slows each guess\n"
        "    (0.1-0.5 s on our laptops, less on a GPU), but a short or dictionary\n"
        "    seed will still fall.\n"
        "  - Same seed + same cover size = same start and same keystream. Two\n"
        "    such files leak the XOR of their payloads: use a new seed per file.\n"
        "  - The seed must reach the verifier through a separate channel.\n"
        "  - Encryption hides the content, not its presence: LSB steganalysis can\n"
        "    still detect that something is embedded. XOR is not authenticated\n"
        "    either; the RSA signature is what catches changes.\n"
        "  - The start can land too near the end for the payload to fit. Protect\n"
        "    then rejects it and the user picks another seed.\n"
        "  - Manual start mode has none of this protection.\n"
        "  - Empty seeds are rejected, and the seed is redacted from evidence."
    )


# ---------- bias demo (FR13 GUI evidence) ----------

def _chi_square(counts: list[int], expected: float) -> float:
    return sum((c - expected) ** 2 / expected for c in counts)


def _chi2_critical_95(df: int) -> float:
    """Wilson-Hilferty approximation of the chi-square 95th percentile (the
    upper one-tailed critical value at alpha=0.05). Close enough for this demo
    without pulling in scipy just to look up a table value (e.g. df=6 gives
    ~12.56 here vs the exact 12.592)."""
    if df <= 0:
        return 0.0
    z = 1.645  # 95th percentile of the standard normal distribution
    return df * (1 - 2 / (9 * df) + z * math.sqrt(2 / (9 * df))) ** 3


def bias_demo(upper: int = 7, trials: int = 20_000) -> dict:
    """Empirical evidence for the FR13 write-up / live demo: runs our real
    rejection-sampling reduction (_unbiased_index) and a naive `% upper`
    reduction the same number of times against a small, deliberately awkward
    (non-power-of-two) upper bound, and reports a chi-square goodness-of-fit
    statistic for each -- proof that rejection sampling removes the structural
    bias naive modulo introduces, rather than just asserting it.
    """
    if upper < 2:
        raise ValueError("upper must be at least 2")
    if trials < upper * 50:
        raise ValueError(f"trials should be at least {upper * 50} for this upper bound")

    rs_counts = [0] * upper
    naive_counts = [0] * upper
    for i in range(trials):
        raw = hashlib.sha256(f"bias-demo-{i}".encode()).digest()
        rs_counts[_unbiased_index(raw, upper)] += 1
        naive_counts[raw[0] % upper] += 1

    expected = trials / upper
    df = upper - 1
    critical = round(_chi2_critical_95(df), 2)

    def summarize(counts):
        chi2 = _chi_square(counts, expected)
        max_dev_pct = max(abs(c - expected) for c in counts) / expected * 100
        return {
            "counts": counts,
            "chi_square": round(chi2, 2),
            "max_deviation_pct": round(max_dev_pct, 2),
            "uniform": chi2 < critical,
        }

    return {
        "upper": upper, "trials": trials, "expected_per_slot": round(expected, 1),
        "df": df, "critical_value_5pct": critical,
        "rejection_sampling": summarize(rs_counts),
        "naive_modulo": summarize(naive_counts),
    }


def describe_bias_demo(result: dict) -> str:
    """Human-readable breakdown of bias_demo()'s output, for the GUI panel."""
    rs, nv = result["rejection_sampling"], result["naive_modulo"]
    upper, crit = result["upper"], result["critical_value_5pct"]
    favoured = 256 % upper

    lines = [
        f"upper={upper} (deliberately awkward -- not a power of two), "
        f"{result['trials']:,} trials each, {result['expected_per_slot']:.0f} expected per bucket.",
        "",
        f"Chi-square critical value at 5% significance (df={result['df']}): {crit}",
        "  Below this: statistically indistinguishable from a uniform distribution.",
        "  Above this: a real, structural bias -- not sampling noise.",
        "",
        f"Rejection sampling (ours): chi-square = {rs['chi_square']} "
        f"({'PASS -- uniform' if rs['uniform'] else 'FAIL -- biased'}), "
        f"max deviation {rs['max_deviation_pct']}% from expected.",
        f"Naive modulo (avoided):    chi-square = {nv['chi_square']} "
        f"({'PASS -- uniform' if nv['uniform'] else 'FAIL -- biased'}), "
        f"max deviation {nv['max_deviation_pct']}% from expected.",
        "",
    ]
    if favoured:
        lines.append(
            f"Why: 256 % {upper} = {favoured}, so naive modulo on a single byte picks "
            f"{favoured} of the {upper} buckets slightly more often."
        )
        lines.append("")
        lines.append(
            "How much it matters for us: very little in practice. A naive "
            "`key % cover_size` over the full 256-bit key would be biased by only "
            "about 2^-230, far too small to measure or exploit. This demo reduces "
            "one byte on purpose so the effect is visible. We use rejection "
            "sampling because it is exactly uniform by design, so there's no need "
            "to argue that the bias is small enough. It is a correctness fix, not "
            "a security measure: unpredictability comes from the secret seed, and "
            "PBKDF2 is what makes guessing slow."
        )
    else:
        lines.append(
            f"Note: 256 is evenly divisible by {upper}, so naive modulo happens to be unbiased "
            "for this particular choice -- pick an odd or prime upper bound (e.g. 7, 13, 100) "
            "to see the contrast clearly."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    import time

    print("FR7 -- derive_start_location() self-test\n")

    # 1. Determinism: same seed + cover_size always agree (encoder == decoder).
    cover_size, seed = 48_000_000, b"correct-horse-battery-staple"
    a = derive_start_location(cover_size, seed)
    b = derive_start_location(cover_size, seed)
    print(f"Determinism: derive(seed) called twice -> {a}, {b}  match={a == b}")
    assert a == b

    # 2. Range check across a spread of cover sizes, including tiny edge cases.
    print("\nRange check (0 <= start < cover_size):")
    for size in (1, 2, 7, 100, 1_000, 48_000_000):
        start = derive_start_location(size, seed)
        ok = 0 <= start < size
        print(f"  cover_size={size:<10} -> start={start:<10} in range: {ok}")
        assert ok

    # 3. Different seeds for the same cover -> different locations (avalanche-ish).
    print("\nSeed sensitivity (same cover_size, related seeds):")
    seed_a, seed_b = b"seed-0000", b"seed-0001"
    start_a = derive_start_location(cover_size, seed_a)
    start_b = derive_start_location(cover_size, seed_b)
    print(f"  {seed_a!r} -> {start_a}")
    print(f"  {seed_b!r} -> {start_b}")
    print(f"  differ: {start_a != start_b}")
    assert start_a != start_b

    # 4. Wrong seed cannot reproduce the right location (what an attacker faces).
    wrong = derive_start_location(cover_size, b"wrong-guess")
    print(f"\nWrong seed: {wrong} (vs correct {a}) -- differ: {wrong != a}")
    assert wrong != a

    # 5. Empty seed is rejected (it would give a fixed, public location).
    try:
        derive_start_location(cover_size, b"")
    except ValueError as exc:
        print(f"\nEmpty seed rejected: {exc}")
    else:
        raise AssertionError("empty seed was accepted")

    # 6. Blob encryption: round-trips, header decrypts on its own, wrong key fails.
    _, key = derive_secrets(cover_size, seed)
    _, wrong_key = derive_secrets(cover_size, b"wrong-guess")
    blob = struct.pack(">I", 11) + b'{"hello":1}' + bytes(256)
    enc = apply_mask(blob, key)
    print(f"\nBlob encryption: header {blob[:4].hex()} -> {enc[:4].hex()}, "
          f"payload {blob[4:10]!r} -> {enc[4:10]!r}")
    assert enc != blob and apply_mask(enc, key) == blob
    assert apply_mask(enc[:4], key) == blob[:4]
    assert apply_mask(enc, wrong_key) != blob
    print("  round-trip OK, header decrypts alone, wrong seed gives garbage")

    # 7. Uniformity of the index reduction: chi-square over 20,000 keys, 10 buckets.
    #    Tests _unbiased_index directly (PBKDF2 output is assumed random), which
    #    gives far more statistical power than a few hundred slow PBKDF2 calls.
    size, draws, buckets = 10_007, 20_000, [0] * 10   # prime size -> rejections happen
    for i in range(draws):
        start = _unbiased_index(hashlib.sha256(f"key-{i}".encode()).digest(), size)
        buckets[start * 10 // size] += 1
    chi2, crit = _chi_square(buckets, draws / 10), _chi2_critical_95(9)
    print(f"\nUniformity ({draws:,} draws over [0, {size:,}), 10 buckets): "
          f"chi-square {chi2:.1f} < {crit:.1f}: {chi2 < crit}")
    assert chi2 < crit

    # 8. Timing: PBKDF2 cost per call (should be well under a second for the GUI).
    t0 = time.perf_counter()
    derive_start_location(cover_size, seed)
    elapsed = time.perf_counter() - t0
    print(f"\nTiming: one derive_start_location() call took {elapsed * 1000:.1f} ms "
          f"({PBKDF2_ITERATIONS:,} PBKDF2 iterations)")

    print("\n" + "=" * 60)
    print(explain_security())
    print("=" * 60)
    print("\nPASS: start_location self-test OK")
