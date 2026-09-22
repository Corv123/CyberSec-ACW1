"""
verdict.py -- Person4's module (FR10 verdict generation, FR13 innovation)

Consumes:
- crypto_utils.verify_signature() / verify_hash() results
- whether image_stego / audio_stego (or video_stego / dct_image_stego, for the
  optional cover types -- see the note below) extraction succeeded at the
  expected location

Produces one of the six verdicts required by the spec (Section 7 / FR10).

Called by gui_pipeline._finish_verdict() as:

    generate_verdict(extraction_successful, signature_valid, hash_valid, context=ctx)

`context` (the `ctx` dict built in gui_pipeline.verify_core) is optional -- if this
function's signature doesn't declare it, the pipeline just calls the three
positional args. We declare it because it carries signal the three booleans alone
can't: whether the extracted bytes even parsed as JSON, and how "text-like" they
are. That's what lets us separate "Wrong Start Location" (we read *something*, but
it's noise, not a payload) from "Payload Missing" (we couldn't read anything at all).

Cover-type note: this module never branches on image/audio/video/DCT -- it only
ever sees the three booleans plus a generic context dict, which gui_pipeline
builds the same way regardless of cover type (verified against the current
gui_pipeline.verify_core: the ctx shape is unchanged by the video/DCT additions).
That means video and DCT covers are already fully supported here with no changes
needed on this side.

Known limitation (worth a line in the innovation/limitations write-up, LO8): this
heuristic isn't airtight. A wrong start location can, by chance, still decode a
plausible-looking length header and even occasionally valid-looking bytes; a
genuinely missing payload can occasionally look "textish" by chance too. A more
robust design would have generate_verdict (or a caller) retry extraction across a
small window of nearby start locations before giving up -- we didn't wire that up
because generate_verdict only receives the verification context, not the file path
or a callback into image_stego/audio_stego. Flagged as a possible v2 improvement.
"""

import tempfile
from pathlib import Path

VERDICTS = [
    "Authentic",
    "Tampered",
    "Signature Invalid",
    "Payload Missing",
    "Wrong Start Location",
    "Cannot Verify",
]

# printable_ratio below this, on a payload that failed to parse as JSON, is our
# signal that we decoded noise rather than a real (just-corrupted) payload.
_TEXTLIKE_THRESHOLD = 0.85


def generate_verdict(extraction_successful: bool, signature_valid: bool, hash_valid,
                      context: dict | None = None) -> str:
    """FR10: decide which of the six VERDICTS applies.

    extraction_successful : did extract_*() return the declared number of
        bytes without raising?
    signature_valid : did crypto_utils.verify_signature() pass on the
        extracted payload/signature?
    hash_valid : True / False / None. None means FR9 (cover-hash check) was
        skipped or not yet implemented -- treat as "not disproved", not as a
        failure.
    context : optional dict from gui_pipeline.verify_core's ctx with richer
        detail (input_ok, payload_parsed, printable_ratio, ...). Safe to omit;
        we fall back to a coarser decision without it.

        Two extra keys, both OPT-IN and both ignored unless present -- the live
        GUI path never sets them, so normal re-verification of an
        already-verified file is completely unaffected unless the team
        deliberately wires this in (see run_attack_simulation()'s replay
        scenario, and the note above on why this isn't the default):
          nonce           -- the payload's nonce (crypto_utils.build_payload()
                              always generates one).
          nonce_registry  -- a mutable set the caller owns. If a nonce we're
                              about to accept as Authentic is already in the
                              set, we return "Tampered" instead (a previously-
                              used signed artifact reappearing) and never add
                              it twice; otherwise we record it and proceed.
    """
    ctx = context or {}

    try:
        # 0. The input file itself was never readable -- nothing downstream is
        #    trustworthy.
        if "input_ok" in ctx and not ctx["input_ok"]:
            return "Cannot Verify"

        # 1. Couldn't read the declared number of bytes at all (raised inside
        #    extract_image/extract_audio/extract_video/extract_dct_image:
        #    cover too small, ran out of data, exception during the two-pass
        #    length-header read). We genuinely have nothing.
        if not extraction_successful:
            return "Payload Missing"

        # 2. We read *something* the right length, but it didn't parse as our
        #    JSON payload schema. That's the fingerprint of reading from the
        #    wrong offset into essentially random cover bits, rather than a
        #    corrupted-but-real payload (a bit-flip inside a real payload
        #    still round-trips through JSON parsing fine -- only the
        #    signature check downstream will catch that). Use printable_ratio
        #    as a second signal so a payload that merely fails a minor schema
        #    check isn't mistaken for pure noise.
        payload_parsed = ctx.get("payload_parsed", True)  # assume parsed if unknown
        printable_ratio = ctx.get("printable_ratio", 1.0)
        if not payload_parsed and printable_ratio < _TEXTLIKE_THRESHOLD:
            return "Wrong Start Location"

        # 3. Structurally a real payload, but the signature doesn't check out:
        #    a hidden bit was flipped after signing (tampering / payload
        #    corruption), or it was signed with a key other than the one
        #    we're verifying against (wrong-key verification).
        if not signature_valid:
            return "Signature Invalid"

        # 4. Signature is valid (so the payload + embedded cover_hash are
        #    exactly as signed), but the cover itself doesn't match that
        #    signed cover_hash -- content was edited outside the payload
        #    region after signing, OR a validly-signed payload+signature pair
        #    was lifted verbatim onto a *different* cover (substitution): the
        #    signature still checks out because the bytes are byte-identical
        #    to what was signed, but cover_hash was computed over the
        #    original cover, not this one.
        if hash_valid is False:
            return "Tampered"

        # 5. Optional replay guard -- see the context= docstring above. Only
        #    engages when the caller explicitly supplies both a nonce and a
        #    registry to check it against.
        registry = ctx.get("nonce_registry")
        nonce = ctx.get("nonce")
        if registry is not None and nonce:
            if nonce in registry:
                return "Tampered"  # a previously-verified signed artifact, reused
            registry.add(nonce)

        # 6. Signature valid, and either the hash matched or FR9 wasn't
        #    available to check it (hash_valid is None) -- nothing we can
        #    check says otherwise.
        return "Authentic"

    except Exception:
        # Anything unexpected (malformed context, etc.) -- never let verdict
        # generation itself crash the GUI.
        return "Cannot Verify"


# ---------------------------------------------------------------------------
# FR13 innovation: a real attack-simulation module.
#
# run_attack_simulation() takes no arguments (see gui_pipeline.call_optional),
# so it builds its own throwaway cover images and RSA keypairs, performs each
# required attack for real (tampering, wrong-key verification, payload
# corruption, wrong-start-location extraction, replay, substitution), and
# runs the results through generate_verdict() via a small self-contained
# extract+verify helper.
#
# IMPORTANT: everything this creates lives in the OS's own temp directory
# (Python's tempfile, e.g. /tmp or %TEMP%) -- NOT inside this project. Nothing
# here is written under the repo, so `git status` never shows anything from
# running this, and there's no tests/evidence/ clutter to clean up or
# accidentally commit. The trade-off: those files are only guaranteed to
# exist for the remainder of the current Python process (they are not
# explicitly deleted either, so a click-to-inspect view in the GUI can still
# open them after the function returns, for as long as the app stays open;
# the OS is responsible for eventually clearing its own temp directory, the
# same as any other program's temp files).
#
# Deliberate scope note: this exercises the IMAGE (LSB) path only, not audio,
# video or DCT, to keep a live-demo run fast and the code manageable. The
# attack *logic* being tested (generate_verdict's decision tree) is shared
# across every cover type, since they all feed it the same shape of context --
# so this is representative coverage, not full coverage of every code path.
# ---------------------------------------------------------------------------

def _row(case: str, expected: str, actual: str, note: str = "",
         cover: str | None = None, file: str | None = None) -> dict:
    """cover / file (optional): paths to the before/after images for this
    scenario, so the GUI can show what the attack actually did, not just the
    verdict it produced. Left unset for scenarios that don't modify a file
    (wrong-start-location, replay) -- the attack there is in how the file is
    read/reused, not in the file itself."""
    return {"case": case, "expected": expected, "actual": actual,
            "result": "PASS" if actual == expected else "FAIL", "note": note,
            "cover": cover, "file": file}


def _real_attack_scenarios() -> list[dict]:
    import crypto_utils
    import image_stego
    from PIL import Image

    rows = []
    tmp = Path(tempfile.mkdtemp(prefix="acw1-attacksim-"))  # OS temp dir, not the repo
    start, lsb = 20, 2

    priv, pub = crypto_utils.generate_keypair(
        priv_path=str(tmp / "priv.pem"), pub_path=str(tmp / "pub.pem"))
    wrong_priv, _ = crypto_utils.generate_keypair(
        priv_path=str(tmp / "wrong_priv.pem"), pub_path=str(tmp / "wrong_pub.pem"))

    def make_cover(path, fill):
        Image.new("RGB", (48, 48), fill).save(path, format="PNG")

    cover_a, cover_b = tmp / "cover_a.png", tmp / "cover_b.png"
    make_cover(cover_a, (80, 120, 160))
    make_cover(cover_b, (200, 40, 90))  # visibly different cover content

    def protect(cover_path, out_path, message, signer=priv):
        cover_hash = crypto_utils.compute_hash(
            crypto_utils.stable_cover_bytes(str(cover_path), "image", lsb))
        payload = crypto_utils.build_payload("SIM-0001", "image", cover_hash, message)
        sig = crypto_utils.sign_payload(payload, signer)
        blob = crypto_utils.pack(payload, sig)
        image_stego.embed_image(str(cover_path), blob, start, lsb, str(out_path))
        return blob

    def decide(stego_path, at_start=start, registry=None):
        """Self-contained mirror of gui_pipeline.verify_core's essential
        steps, kept local to avoid a circular import (gui_pipeline already
        imports this module)."""
        ctx = {"input_ok": True, "payload_parsed": False, "printable_ratio": 0.0,
               "nonce": None, "nonce_registry": registry}
        try:
            blob = image_stego.extract_image(str(stego_path), at_start, lsb)
        except Exception:
            return generate_verdict(False, False, None, context=ctx)
        try:
            payload_bytes, sig = crypto_utils.unpack(blob)
        except Exception:
            return generate_verdict(True, False, None, context=ctx)

        printable = sum(1 for b in payload_bytes if 32 <= b < 127 or b in (9, 10, 13))
        ctx["printable_ratio"] = printable / max(1, len(payload_bytes))

        payload = None
        try:
            payload = crypto_utils.parse_payload(payload_bytes)
            ctx["payload_parsed"] = True
            ctx["nonce"] = payload.get("nonce")
        except Exception:
            pass

        sig_valid = crypto_utils.verify_signature(payload_bytes, sig, pub)
        hash_valid = None
        if ctx["payload_parsed"]:
            actual_hash = crypto_utils.compute_hash(
                crypto_utils.stable_cover_bytes(str(stego_path), "image", lsb))
            hash_valid = (actual_hash == payload.get("cover_hash"))
        return generate_verdict(True, sig_valid, hash_valid, context=ctx)

    # 1. Tampering / payload corruption -- flip one hidden bit inside the
    #    payload body of an otherwise genuine stego file.
    genuine = tmp / "genuine.png"
    protect(cover_a, genuine, "attack-sim: genuine message")
    tampered = tmp / "tampered.png"
    image_stego.make_tampered_image(str(genuine), str(tampered), start, lsb)
    rows.append(_row("Tampering / payload corruption -- 1 hidden bit flipped",
                     "Signature Invalid", decide(tampered),
                     note="Diff highlights the single flipped bit inside the payload region.",
                     cover=str(genuine), file=str(tampered)))

    # 2. Wrong-key verification -- signed with a DIFFERENT private key than
    #    the one being verified against. The diff shows exactly where the
    #    signature lives: the JSON payload text is identical, only the
    #    trailing ~256-byte signature region differs.
    wrong_key_stego = tmp / "wrong_key.png"
    protect(cover_a, wrong_key_stego, "attack-sim: wrong signing key", signer=wrong_priv)
    rows.append(_row("Wrong-key verification -- signed with a different private key",
                     "Signature Invalid", decide(wrong_key_stego),
                     note="Diff shows only the signature region changing -- same message, different key.",
                     cover=str(genuine), file=str(wrong_key_stego)))

    # 3. Wrong-start-location extraction -- correct file, wrong offset. No
    #    file is modified here; the attack is in how it's read.
    rows.append(_row("Wrong-start-location extraction (start+1)",
                     "Wrong Start Location", decide(genuine, at_start=start + 1),
                     note="Same file both times -- the attack is reading from offset "
                          f"{start + 1} instead of {start}, not a file change.",
                     cover=str(genuine), file=str(genuine)))

    # 4. Replay attempt -- the SAME genuinely-signed file, verified twice.
    #    Own throwaway in-memory registry -- never touches the live app's
    #    default path (see generate_verdict's context docstring).
    registry = set()
    first = decide(genuine, registry=registry)
    second = decide(genuine, registry=registry)
    rows.append(_row("Replay attempt -- first use of a signed file",
                     "Authentic", first,
                     note="Same bytes as the row below -- only the second use is rejected.",
                     cover=str(genuine), file=str(genuine)))
    rows.append(_row("Replay attempt -- SAME signed file reused",
                     "Tampered", second,
                     note="Only rejected because this simulation opts in to nonce_registry; "
                          "the live app does not do this by default.",
                     cover=str(genuine), file=str(genuine)))

    # 5. Substitution attempt -- a validly-signed payload+signature lifted
    #    verbatim off one cover and re-embedded onto a DIFFERENT cover. The
    #    diff below (cover_b vs substituted) only shows the small LSB region
    #    the attacker touched -- it does NOT show the actual problem, which
    #    is that the signed cover_hash inside those unchanged payload bytes
    #    points to cover_a, not cover_b. That's deliberate: it's exactly why
    #    a naive "does the image look edited?" check would miss this attack,
    #    and why FR9's cover-hash binding is the part that actually catches it.
    blob = protect(cover_a, tmp / "source.png", "attack-sim: substitution source")
    substituted = tmp / "substituted.png"
    image_stego.embed_image(str(cover_b), blob, start, lsb, str(substituted))
    rows.append(_row("Substitution attempt -- valid payload moved onto a different cover",
                     "Tampered", decide(substituted),
                     note="Pixel diff looks tiny -- the real tell is invisible in pixels: "
                          "cover_hash inside the payload points to cover_a, not this image.",
                     cover=str(cover_b), file=str(substituted)))

    return rows


_SYNTHETIC_SCENARIOS = [
    {
        "case": "Clean verify, hash confirmed",
        "extraction_successful": True, "signature_valid": True, "hash_valid": True,
        "context": {"input_ok": True, "payload_parsed": True, "printable_ratio": 1.0},
        "expected": "Authentic",
    },
    {
        "case": "Clean verify, FR9 hash check unavailable",
        "extraction_successful": True, "signature_valid": True, "hash_valid": None,
        "context": {"input_ok": True, "payload_parsed": True, "printable_ratio": 1.0},
        "expected": "Authentic",
    },
    {
        "case": "No payload embedded at all (original cover)",
        "extraction_successful": False, "signature_valid": False, "hash_valid": None,
        "context": {"input_ok": True, "payload_parsed": False, "printable_ratio": 0.0},
        "expected": "Payload Missing",
    },
    {
        "case": "Corrupted / unreadable cover file",
        "extraction_successful": False, "signature_valid": False, "hash_valid": None,
        "context": {"input_ok": False},
        "expected": "Cannot Verify",
    },
]


def _synthetic_scenarios() -> list[dict]:
    """Fast, file-free decision-logic coverage -- complements the real attacks
    above by hitting a couple of branches (missing payload, unreadable file)
    that aren't naturally "attacks" so don't need a real-file scenario."""
    rows = []
    for s in _SYNTHETIC_SCENARIOS:
        actual = generate_verdict(
            s["extraction_successful"], s["signature_valid"], s["hash_valid"],
            context=s["context"],
        )
        rows.append(_row(s["case"], s["expected"], actual))
    return rows


def run_attack_simulation():
    """FR13: real attacks against real, throwaway-generated files (tampering,
    wrong-key verification, payload corruption, wrong-start-location
    extraction, replay, substitution), plus a couple of fast synthetic checks
    for branches that aren't naturally framed as an "attack". Returns a list
    of dicts (rendered as a table by gui_components.CaseTable on the
    Innovation tab).

    Everything real-file based happens in the OS temp directory, never inside
    this project -- see the module-level note above _real_attack_scenarios().

    If the real-file section fails for an environment reason (e.g. Pillow
    missing, or Person5/Person1's functions not yet available), that failure
    is reported as a single row rather than losing the whole table -- the
    synthetic rows still run and still report.
    """
    rows = []
    try:
        rows.extend(_real_attack_scenarios())
    except Exception as exc:
        rows.append({"case": "Real attack simulation (image_stego/crypto_utils)",
                     "expected": "(all scenarios run)", "actual": f"{type(exc).__name__}: {exc}",
                     "result": "FAIL", "note": "environment/dependency issue, see error",
                     "cover": None, "file": None})
    rows.extend(_synthetic_scenarios())
    return rows


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("FR10/FR13 -- verdict.py self-test\n")
    rows = run_attack_simulation()
    width = max(len(r["case"]) for r in rows)
    failed = 0
    for r in rows:
        mark = r["result"]
        if mark != "PASS":
            failed += 1
        note = f"  ({r['note']})" if r.get("note") else ""
        print(f"  [{mark}] {r['case']:<{width}}  expected={r['expected']:<10} actual={r['actual']}{note}")

    print()
    if failed:
        print(f"FAIL: {failed}/{len(rows)} scenario(s) did not match expected verdict.")
        raise SystemExit(1)
    print(f"PASS: all {len(rows)} scenarios produced the expected verdict.")