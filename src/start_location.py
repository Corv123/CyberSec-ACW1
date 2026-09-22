"""
start_location.py -- Person3's module (FR7 variable start location, FR13 innovation)

Both image_stego.py and audio_stego.py (via gui_pipeline.py) call
derive_start_location() so the encoder and decoder always agree on where embedding
began, without the location ever being transmitted or stored in the clear.

Method (see explain_security() for the full write-up):
  1. Stretch the shared `seed` with PBKDF2-HMAC-SHA256 (many iterations). This is
     the actual security measure: the stego file and its cover_size are public, so
     an attacker can already try candidate seeds and use the RSA signature as a
     correctness oracle (derive -> extract -> verify_signature). Stretching makes
     every guess in that brute-force loop expensive instead of a single hash call.
  2. Use the stretched key as an HMAC-SHA256 keystream (counter mode) and reduce it
     to an index in [0, cover_size) by rejection sampling, so every location is
     equally likely -- no modulo bias.

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


def derive_start_location(cover_size: int, seed: bytes) -> int:
    """Given the cover's total addressable size (pixels*channels for images,
    samples*sample_width for audio -- see gui_pipeline.py) and a shared seed,
    deterministically produce a start index. Same seed + same cover_size always
    produces the same location -- that's what lets the decoder find it again
    without the location being sent in the clear.

    Returns: an integer index into the cover's flat data array, 0 <= index < cover_size.
    """
    if cover_size <= 0:
        raise ValueError("cover_size must be positive")
    if not isinstance(seed, bytes):
        raise TypeError("seed must be bytes")

    stretched = _stretch_seed(seed, cover_size)
    return _unbiased_index(stretched, cover_size)


def explain_security() -> str:
    """Short explanation for the innovation write-up and live-demo Q&A."""
    return (
        "How it works: the shared `seed` (a passphrase entered once and reused "
        "for both Protect and Verify) is stretched with PBKDF2-HMAC-SHA256 "
        f"({PBKDF2_ITERATIONS:,} iterations) into a 256-bit key. That key drives an "
        "HMAC-SHA256 counter-mode keystream, which is reduced to an index in "
        "[0, cover_size) by rejection sampling -- every location in range is "
        "equally likely (no modulo bias), and the same seed + cover_size always "
        "reproduces the same start location.\n\n"
        "Why it resists guessing: the stego file and its cover_size are public, so "
        "an attacker can already try candidate seeds and use the RSA signature as "
        "a correctness oracle (derive -> extract -> verify_signature). Without "
        "stretching, that loop costs one SHA-256 evaluation per guess, making "
        "short or dictionary seeds crackable in seconds. PBKDF2 makes every guess "
        f"cost {PBKDF2_ITERATIONS:,} SHA-256 evaluations instead -- that cost, not the "
        "choice of hash function, is the actual defence.\n\n"
        "Limitations: all of the security lives in the secrecy and entropy of "
        "`seed`. A short, reused, or dictionary seed is still crackable, just "
        "slower; a leaked seed reveals the start location outright, since "
        "cover_size is not secret; and the iteration count is a fixed constant "
        "here rather than tuned per deployment. This protects the location from a "
        "passive or blind attacker, not from one who already knows or can guess "
        "the seed."
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
            f"Inference: 256 % {upper} = {favoured}, so naive modulo structurally favours "
            f"{favoured} of the {upper} buckets on every single draw -- a fixed pattern, not "
            "chance. An attacker brute-forcing seeds could exploit that pattern to prioritise "
            "the favoured region and shrink their effective search space. Rejection sampling "
            "removes the pattern entirely: every location in range is equally likely by "
            "construction, which is what the brute-force cost claims in explain_security() "
            "rely on."
        )
    else:
        lines.append(
            f"Note: 256 is evenly divisible by {upper}, so naive modulo happens to be unbiased "
            "for this particular choice -- pick an odd or prime upper bound (e.g. 7, 13, 100) "
            "to see the contrast clearly."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    import statistics
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

    # 4. Wrong seed cannot reproduce the right location (what an attacker faces).
    print(f"\nWrong seed: {derive_start_location(cover_size, b'wrong-guess')} "
          f"(vs correct {a}) -- differ: {derive_start_location(cover_size, b'wrong-guess') != a}")

    # 5. Coarse uniformity spot-check: many seeds, bucket the results.
    print("\nUniformity spot-check (200 seeds, 8 buckets, expect roughly even spread):")
    size, buckets = 10_000, [0] * 8
    for i in range(200):
        start = derive_start_location(size, f"seed-{i}".encode())
        buckets[start * 8 // size] += 1
    print(f"  bucket counts: {buckets}  (mean {statistics.mean(buckets):.1f}, "
          f"stdev {statistics.pstdev(buckets):.1f})")

    # 6. Timing: PBKDF2 cost per call (should be well under a second for the GUI).
    t0 = time.perf_counter()
    derive_start_location(cover_size, seed)
    elapsed = time.perf_counter() - t0
    print(f"\nTiming: one derive_start_location() call took {elapsed * 1000:.1f} ms "
          f"({PBKDF2_ITERATIONS:,} PBKDF2 iterations)")

    print("\n" + "=" * 60)
    print(explain_security())
    print("=" * 60)
    print("\nPASS: start_location self-test OK")
