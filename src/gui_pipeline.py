"""
gui_pipeline.py -- Person6's integration layer (FR11 case demonstration, FR12 evidence)

No Tkinter in here: this module wires the other five modules together and
returns plain data (Step / RunResult) that gui_components.py renders. That keeps
it testable without a display and lets any teammate call it directly:

    from gui_pipeline import protect, verify, run_case_suite, fr_status
    result = verify("samples/stego_image_short.png", {"start": 100, "lsb_depth": 2})
    print(result.verdict, [s.status for s in result.steps])

Unfinished teammate functions (still raising NotImplementedError) are reported as
"pending" steps instead of crashing the GUI. When a teammate implements their
function, the GUI picks it up automatically -- no GUI change needed.

Integration points for teammates (ALIGNMENT.md Section 5):
- Person3: start_location.derive_start_location(cover_size, seed) -- used when the
  GUI's start mode is "derive". cover_size = w*h*3 (image) or
  nframes*nchannels*sampwidth (audio), matching the stego modules.
- Person4: verdict.generate_verdict(extraction_successful, signature_valid, hash_valid)
  hash_valid may be None (hash not checkable yet). If your function also accepts a
  `context` keyword (or **kwargs), it receives the full dict built in
  _verdict_context() -- e.g. to tell "Payload Missing" from "Wrong Start Location".
- Person4: verdict.run_attack_simulation() -- return a list of dicts (rendered as a
  table) or a string. Shown on the Innovation tab.
- Person5: optional crypto_utils.stable_cover_bytes(path, cover_type, lsb_depth) -> bytes
  (the part of the cover embedding never touches). If defined, it is used for
  cover_hash on protect AND checked on verify (FR9). Until then, protect uses the
  placeholder whole-file hash and verify reports FR9 as pending.
"""

from __future__ import annotations

import ast
import inspect
import json
import math
import platform
import shutil
import subprocess
import sys
import textwrap
import wave
from array import array
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageChops, ImageOps

import audio_stego
import crypto_utils
import image_stego
import start_location
import verdict

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PRIVATE_KEY = ROOT / "keys" / "private_key.pem"
DEFAULT_PUBLIC_KEY = ROOT / "keys" / "public_key.pem"
EVIDENCE_ROOT = ROOT / "tests" / "evidence"

IMAGE_SUFFIXES = {".png", ".bmp", ".tif", ".tiff", ".jpg", ".jpeg", ".gif"}
AUDIO_SUFFIXES = {".wav", ".wave"}

VERDICTS = list(verdict.VERDICTS)
POSITIVE_VERDICTS = {"Authentic"}
WARNING_VERDICTS = {"Cannot Verify"}

# ALIGNMENT.md Section 7 test data. TODO(team): replace the short/large texts with
# the chosen Learning Outcome and the spec's Project Overview paragraph.
MESSAGE_PRESETS = {
    "short": "Short test message -- replace with the Learning Outcome chosen by the team.",
    "large": (
        "Large test message -- replace with the Project Overview paragraph from the "
        "assignment spec. This placeholder is deliberately long so the capacity check, "
        "embedding and extraction are exercised with a payload several times larger "
        "than the short case. The tool hides a signed, hashed verification payload "
        "inside an image and an audio file using LSB replacement, then extracts and "
        "checks it, returning one of six verdicts: Authentic, Tampered, Signature "
        "Invalid, Payload Missing, Wrong Start Location, or Cannot Verify. The payload "
        "carries a media ID, a UTC timestamp, the cover type, a SHA-256 cover hash, a "
        "random nonce against replay, this message, and metadata describing the "
        "embedding parameters, and it is signed with RSA-2048 using PKCS#1 v1.5."
    ),
    "custom": "Custom scenario: evidence photo EV-2026-0412 captured by Officer A at 10:15.",
}

STATUS_OK, STATUS_FAIL, STATUS_PENDING, STATUS_INFO, STATUS_SKIP = (
    "ok", "fail", "pending", "info", "skip")


# ---------- result data ----------

@dataclass
class Step:
    """One row in the GUI's step list. status: ok | fail | pending | info | skip."""
    fr: str
    title: str
    status: str
    detail: str = ""


@dataclass
class RunResult:
    action: str                      # "protect" | "verify"
    kind: str | None = None          # "image" | "audio"
    steps: list = field(default_factory=list)
    outcome: str = ""                # verdict (verify) or Protected/Rejected/Error (protect)
    provisional: bool = False        # True when verdict.py is not implemented yet
    params: dict = field(default_factory=dict)
    payload: dict | None = None
    outputs: dict = field(default_factory=dict)   # name -> path
    stats: dict = field(default_factory=dict)
    evidence_dir: str | None = None

    def add(self, fr, title, status, detail=""):
        step = Step(fr, title, status, detail)
        self.steps.append(step)
        return step

    def to_dict(self):
        d = asdict(self)
        d["polarity"] = polarity(self.outcome)
        return d


def polarity(outcome: str) -> str:
    """positive | negative | warning -- drives the green/red/amber colouring."""
    if outcome in POSITIVE_VERDICTS or outcome == "Protected":
        return "positive"
    if outcome in WARNING_VERDICTS or outcome in ("", "Error"):
        return "warning"
    return "negative"


# ---------- stub detection (for pending FRs) ----------

def is_stub(fn) -> bool:
    """True if `fn`'s body (ignoring the docstring) is only `raise NotImplementedError`."""
    if fn is None:
        return True
    try:
        node = ast.parse(textwrap.dedent(inspect.getsource(fn))).body[0]
    except (OSError, TypeError, SyntaxError, IndexError):
        return False
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return (len(body) == 1 and isinstance(body[0], ast.Raise)
            and "NotImplementedError" in ast.dump(body[0]))


def _stable_bytes_hook():
    return getattr(crypto_utils, "stable_cover_bytes", None)


# ---------- FR1 / FR2: input handling ----------

def detect_kind(path) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in AUDIO_SUFFIXES:
        return "audio"
    if suffix in IMAGE_SUFFIXES:
        return "image"
    raise ValueError(f"Unsupported file type '{suffix}'. Use PNG (image) or WAV (audio).")


def inspect_media(path) -> tuple[str, dict, list]:
    """Return (kind, info, warnings). Raises on unreadable / unsupported input."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    kind = detect_kind(path)
    warnings = []
    if kind == "image":
        try:
            with Image.open(path) as im:
                info = {"format": im.format, "width": im.width, "height": im.height,
                        "mode": im.mode}
        except OSError as exc:
            raise ValueError(f"Not a readable image: {exc}") from exc
        info["cover_size"] = info["width"] * info["height"] * 3
        if info["format"] == "JPEG":
            warnings.append("JPEG input: stego is saved as PNG. Never re-save it as JPEG "
                            "-- lossy compression destroys the LSB payload.")
        if info["mode"] not in ("RGB", "L", "P"):
            warnings.append(f"Mode {info['mode']}: converted to RGB, alpha is dropped.")
    else:
        try:
            with wave.open(str(path), "rb") as wf:
                p = wf.getparams()
        except (wave.Error, EOFError) as exc:
            raise ValueError(f"Not a readable WAV/PCM file: {exc}") from exc
        info = {"format": "WAV", "channels": p.nchannels, "sample_width_bytes": p.sampwidth,
                "sample_rate": p.framerate, "frames": p.nframes,
                "duration_s": round(p.nframes / p.framerate, 2) if p.framerate else 0,
                "cover_size": p.nframes * p.nchannels * p.sampwidth}
    info["file_bytes"] = path.stat().st_size
    return kind, info, warnings


def describe_media(kind, info) -> str:
    if kind == "image":
        return (f"{info['format']} image, {info['width']}x{info['height']} {info['mode']}, "
                f"{info['cover_size']:,} colour samples")
    return (f"WAV audio, {info['channels']} ch, {info['sample_width_bytes'] * 8}-bit, "
            f"{info['sample_rate']} Hz, {info['duration_s']} s, "
            f"{info['cover_size']:,} sample bytes")


def _input_step(result: RunResult, path) -> dict | None:
    fr = "FR1/FR2"
    try:
        kind, info, warnings = inspect_media(path)
    except Exception as exc:
        result.add(fr, "Load input file", STATUS_FAIL, f"{type(exc).__name__}: {exc}")
        return None
    result.kind = kind
    fr = "FR1" if kind == "image" else "FR2"
    detail = describe_media(kind, info)
    if warnings:
        detail += "\nWarning: " + "\nWarning: ".join(warnings)
    result.add(fr, f"Load {kind} input", STATUS_OK, detail)
    return info


# ---------- FR7: start location ----------

def default_params(**overrides) -> dict:
    params = {"start_mode": "manual", "start": 100, "seed": "", "lsb_depth": 2,
              "low_byte_only": False}
    params.update(overrides)
    return params


def _resolve_start(result: RunResult, cover_size: int, params: dict) -> int | None:
    manual = int(params.get("start", 0))
    start = manual
    if params.get("start_mode") == "derive":
        fn = start_location.derive_start_location
        seed = str(params.get("seed", "")).encode("utf-8")
        try:
            if is_stub(fn):
                raise NotImplementedError
            start = int(fn(cover_size, seed))
            result.add("FR7", "Derive start location from seed", STATUS_OK,
                       f"derive_start_location(cover_size={cover_size:,}, seed) -> {start}")
        except NotImplementedError:
            result.add("FR7", "Derive start location from seed", STATUS_PENDING,
                       "start_location.derive_start_location() not implemented yet "
                       f"(Person3). Fell back to manual start location {manual}.")
        except Exception as exc:
            result.add("FR7", "Derive start location from seed", STATUS_FAIL,
                       f"{type(exc).__name__}: {exc}")
            return None
    else:
        result.add("FR7", "Start location", STATUS_INFO,
                   f"Manual start location {manual} (seed-derived mode not selected).")
    if not 0 <= start < cover_size:
        result.add("FR7", "Start location in range", STATUS_FAIL,
                   f"Start {start} is outside the cover (0..{cover_size - 1}).")
        return None
    result.params["start_location"] = start
    return start


# ---------- FR9 helpers ----------

def _cover_hash_for_protect(result: RunResult, cover, kind, lsb_depth) -> str:
    hook = _stable_bytes_hook()
    if hook is not None:
        try:
            digest = crypto_utils.compute_hash(hook(str(cover), kind, lsb_depth))
            result.add("FR9", "Hash stable part of cover", STATUS_OK, f"cover_hash = {digest}")
            return digest
        except NotImplementedError:
            pass
    digest = crypto_utils.compute_hash(Path(cover).read_bytes())
    result.add("FR9", "Hash cover", STATUS_PENDING,
               "Placeholder: SHA-256 of the whole original file (ALIGNMENT.md Section 10). "
               "It cannot be re-checked after embedding until Person5 adds "
               "crypto_utils.stable_cover_bytes().\ncover_hash = " + digest)
    return digest


# ---------- protect (FR1-FR7, FR9) ----------

def _capacity_bytes(kind, cover_size, start, lsb, low_byte_only, sampwidth=2) -> int:
    usable = cover_size - start
    if kind == "audio" and low_byte_only and sampwidth > 1:
        usable = (cover_size - start) // sampwidth
    return max(0, usable * lsb // 8)


def protect_core(cover, message, params, private_key_path=DEFAULT_PRIVATE_KEY,
                 out_path=None, media_id=None) -> RunResult:
    """Build + sign + embed. Writes the stego file to out_path (no evidence folder)."""
    result = RunResult("protect", params=dict(params))
    result.outcome = "Error"
    info = _input_step(result, cover)
    if info is None:
        return result
    kind = result.kind
    lsb = int(params.get("lsb_depth", 2))
    low = bool(params.get("low_byte_only")) and kind == "audio"
    start = _resolve_start(result, info["cover_size"], params)
    if start is None:
        return result

    cover_hash = _cover_hash_for_protect(result, cover, kind, lsb)

    media_id = media_id or f"{'IMG' if kind == 'image' else 'AUD'}-{datetime.now():%Y%m%d%H%M%S}"
    metadata = {"team": "P1-4", "lsb_depth": lsb, "start_mode": params.get("start_mode", "manual")}
    if kind == "audio":
        metadata["low_byte_only"] = low
    try:
        payload = crypto_utils.build_payload(media_id, kind, cover_hash, message, metadata)
        result.payload = crypto_utils.parse_payload(payload)
        result.add("FR3", "Build payload", STATUS_OK,
                   f"{len(payload):,} bytes JSON, media_id={media_id}, "
                   f"nonce={result.payload['nonce']}")
    except Exception as exc:
        result.add("FR3", "Build payload", STATUS_FAIL, f"{type(exc).__name__}: {exc}")
        return result

    try:
        priv = crypto_utils.load_private_key(str(private_key_path))
        signature = crypto_utils.sign_payload(payload, priv)
        blob = crypto_utils.pack(payload, signature)
        result.add("FR4", "Sign payload (RSA-2048, PKCS#1 v1.5)", STATUS_OK,
                   f"key: {private_key_path}\nsignature: {signature.hex()[:48]}...")
    except Exception as exc:
        result.add("FR4", "Sign payload", STATUS_FAIL, f"{type(exc).__name__}: {exc}")
        return result

    fr = "FR5" if kind == "image" else "FR6"
    needed = crypto_utils.total_embed_size(payload)
    available = _capacity_bytes(kind, info["cover_size"], start, lsb, low,
                                info.get("sample_width_bytes", 1))
    result.stats.update(needed_bytes=needed, available_bytes=available)
    try:
        if kind == "image":
            fits = image_stego.check_capacity(str(cover), needed, lsb, start)
        else:
            fits = audio_stego.check_capacity(str(cover), needed, lsb, start, low)
    except Exception as exc:
        result.add(fr, "Capacity check", STATUS_FAIL, f"{type(exc).__name__}: {exc}")
        return result
    usage = f"needs {needed:,} bytes, cover holds ~{available:,} bytes " \
            f"from start {start} at {lsb} LSB(s)"
    if not fits:
        result.add(fr, "Capacity check", STATUS_FAIL, "Payload too large: " + usage)
        result.outcome = "Rejected"
        return result
    result.add(fr, "Capacity check", STATUS_OK, usage)

    if out_path is None:
        raise ValueError("out_path is required")
    out_path = Path(out_path).with_suffix(".png" if kind == "image" else ".wav")
    try:
        if kind == "image":
            image_stego.embed_image(str(cover), blob, start, lsb, str(out_path))
        else:
            audio_stego.embed_audio(str(cover), blob, start, lsb, str(out_path), low)
    except Exception as exc:
        result.add(fr, f"Embed into {kind}", STATUS_FAIL, f"{type(exc).__name__}: {exc}")
        return result
    result.add(fr, f"Embed into {kind}", STATUS_OK, f"stego written to {out_path}")
    result.outputs["stego"] = str(out_path)
    result.outcome = "Protected"
    return result


def protect(cover, message, params, private_key_path=DEFAULT_PRIVATE_KEY,
            media_id=None) -> RunResult:
    """Protect + before/after comparison + FR12 evidence folder."""
    kind = _safe_kind(cover)
    ev = Evidence("protect", kind)
    result = protect_core(cover, message, params, private_key_path,
                          ev.dir / "stego", media_id)
    if result.outputs.get("stego"):
        try:
            result.stats.update(compare_media(cover, result.outputs["stego"],
                                              ev.dir / "difference.png"))
            if result.stats.get("diff_image"):
                result.outputs["difference"] = result.stats["diff_image"]
            result.add("FR11", "Before/after comparison", STATUS_INFO,
                       result.stats.get("summary", ""))
        except Exception as exc:
            result.add("FR11", "Before/after comparison", STATUS_SKIP, str(exc))
    ev.save_run(result, inputs={"cover": cover, "private_key": private_key_path},
                message=message)
    return result


# ---------- verify (FR1/FR2, FR7-FR10) ----------

def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / len(data)


def verify_core(path, params, public_key_path=DEFAULT_PUBLIC_KEY) -> RunResult:
    result = RunResult("verify", params=dict(params))
    ctx = {"input_ok": False, "input_error": None, "extraction_successful": False,
           "extraction_error": None, "payload_parsed": False, "printable_ratio": 0.0,
           "signature_valid": False, "hash_valid": None, "start_location": None,
           "lsb_depth": int(params.get("lsb_depth", 2)), "cover_type": None}
    info = _input_step(result, path)
    if info is None:
        ctx["input_error"] = result.steps[-1].detail
        return _finish_verdict(result, ctx)
    ctx["input_ok"], ctx["cover_type"] = True, result.kind
    kind, lsb = result.kind, ctx["lsb_depth"]
    low = bool(params.get("low_byte_only")) and kind == "audio"

    start = _resolve_start(result, info["cover_size"], params)
    if start is None:
        ctx["input_error"] = "start location unavailable"
        return _finish_verdict(result, ctx)
    ctx["start_location"] = start

    # FR8: extraction
    try:
        if kind == "image":
            blob = image_stego.extract_image(str(path), start, lsb)
        else:
            blob = audio_stego.extract_audio(str(path), start, lsb, low)
        payload_bytes, signature = crypto_utils.unpack(blob)
        ctx["extraction_successful"] = True
        result.add("FR8", f"Extract hidden blob from {kind}", STATUS_OK,
                   f"length header = {len(payload_bytes):,} bytes\n"
                   f"blob = 4 + {len(payload_bytes):,} + {len(signature)} = {len(blob):,} bytes\n"
                   f"read from start {start} at {lsb} LSB(s)")
    except Exception as exc:
        ctx["extraction_error"] = f"{type(exc).__name__}: {exc}"
        result.add("FR8", f"Extract hidden blob from {kind}", STATUS_FAIL,
                   ctx["extraction_error"] + "\nLikely causes: no payload in this file, wrong "
                   "start location, wrong LSB depth / low-byte setting, or a truncated file.")
        return _finish_verdict(result, ctx)

    ctx["printable_ratio"] = round(_printable_ratio(payload_bytes), 3)
    try:
        result.payload = crypto_utils.parse_payload(payload_bytes)
        ctx["payload_parsed"] = isinstance(result.payload, dict)
        missing = [k for k in ("media_id", "timestamp", "cover_type", "cover_hash",
                               "nonce", "message") if k not in (result.payload or {})]
        result.add("FR3", "Decode payload JSON", STATUS_OK if not missing else STATUS_INFO,
                   "All ALIGNMENT.md Section 4 fields present." if not missing
                   else f"Missing fields: {missing}")
    except Exception as exc:
        result.add("FR3", "Decode payload JSON", STATUS_FAIL,
                   f"{type(exc).__name__}: {exc}\n{ctx['printable_ratio']:.0%} of the bytes "
                   f"are printable text. Preview: {payload_bytes[:80]!r}")

    try:
        pub = crypto_utils.load_public_key(str(public_key_path))
        ctx["signature_valid"] = crypto_utils.verify_signature(payload_bytes, signature, pub)
        result.add("FR4", "Verify RSA signature", STATUS_OK if ctx["signature_valid"] else STATUS_FAIL,
                   ("Signature matches the payload and public key." if ctx["signature_valid"]
                    else "Signature does NOT match: payload altered, or signed with a different "
                         "private key.") + f"\nkey: {public_key_path}")
    except Exception as exc:
        result.add("FR4", "Verify RSA signature", STATUS_FAIL, f"{type(exc).__name__}: {exc}")

    hook = _stable_bytes_hook()
    expected = (result.payload or {}).get("cover_hash") if ctx["payload_parsed"] else None
    if expected is None:
        result.add("FR9", "Check cover hash", STATUS_SKIP, "No cover_hash available.")
    elif hook is None:
        result.add("FR9", "Check cover hash", STATUS_PENDING,
                   "crypto_utils.stable_cover_bytes() not implemented yet (Person5). "
                   "Edits to the media outside the payload are not detected.")
    else:
        try:
            ctx["hash_valid"] = crypto_utils.verify_hash(hook(str(path), kind, lsb), expected)
            result.add("FR9", "Check cover hash", STATUS_OK if ctx["hash_valid"] else STATUS_FAIL,
                       "Cover matches the signed hash." if ctx["hash_valid"]
                       else "Cover content differs from the signed cover_hash.")
        except Exception as exc:
            result.add("FR9", "Check cover hash", STATUS_FAIL, f"{type(exc).__name__}: {exc}")
    return _finish_verdict(result, ctx)


def provisional_verdict(ctx: dict) -> str:
    """GUI stand-in used ONLY while verdict.generate_verdict() is unimplemented."""
    if not ctx["input_ok"]:
        return "Cannot Verify"
    if not ctx["extraction_successful"]:
        return "Payload Missing"
    if not ctx["signature_valid"]:
        if not ctx["payload_parsed"] and ctx["printable_ratio"] < 0.9:
            return "Wrong Start Location"   # bits were read, but they are not a payload
        return "Signature Invalid"
    if ctx["hash_valid"] is False:
        return "Tampered"
    return "Authentic"


def _finish_verdict(result: RunResult, ctx: dict) -> RunResult:
    fn = verdict.generate_verdict
    result.stats["verdict_context"] = ctx
    try:
        if is_stub(fn):
            raise NotImplementedError
        sig = inspect.signature(fn)
        kwargs = {}
        if "context" in sig.parameters or any(
                p.kind == p.VAR_KEYWORD for p in sig.parameters.values()):
            kwargs["context"] = ctx
        outcome = fn(ctx["extraction_successful"], ctx["signature_valid"], ctx["hash_valid"],
                     **kwargs)
        result.outcome = outcome
        known = outcome in VERDICTS
        result.add("FR10", "Verdict (verdict.generate_verdict)",
                   STATUS_OK if known else STATUS_FAIL,
                   outcome if known else f"Unexpected verdict value {outcome!r}")
    except NotImplementedError:
        result.outcome = provisional_verdict(ctx)
        result.provisional = True
        result.add("FR10", "Verdict", STATUS_PENDING,
                   f"verdict.generate_verdict() not implemented yet (Person4). "
                   f"GUI provisional verdict: {result.outcome}")
    except Exception as exc:
        result.outcome = "Cannot Verify"
        result.add("FR10", "Verdict", STATUS_FAIL, f"verdict.py raised {type(exc).__name__}: {exc}")
    return result


def verify(path, params, public_key_path=DEFAULT_PUBLIC_KEY) -> RunResult:
    """Verify + FR12 evidence folder."""
    ev = Evidence("verify", _safe_kind(path))
    result = verify_core(path, params, public_key_path)
    ev.save_run(result, inputs={"file": path, "public_key": public_key_path})
    return result


# ---------- FR11: positive / negative case demonstration ----------

@dataclass
class Case:
    id: str
    title: str
    expected: str               # a verdict, or "Rejected" for protect-side cases
    fr: str
    blocked_by: tuple = ()      # FRs that must exist before this case can pass
    description: str = ""


CASES = [
    Case("pos_short", "Authentic -- short message", "Authentic", "FR3-FR10"),
    Case("pos_large", "Authentic -- large message", "Authentic", "FR3-FR10"),
    Case("pos_custom", "Authentic -- custom message", "Authentic", "FR3-FR10"),
    Case("tamper_payload", "Tampered payload (one hidden bit flipped)", "Signature Invalid",
         "FR4", description="make_tampered_image/make_tampered_audio on the short stego"),
    Case("wrong_key", "Signed with a different private key", "Signature Invalid", "FR4",
         description="temporary keypair; verified with the team public key"),
    Case("media_edit", "Media edited outside the payload", "Tampered", "FR9",
         blocked_by=("FR9",), description="high bits of the last pixels/samples changed"),
    Case("wrong_start", "Wrong start location (+1)", "Wrong Start Location", "FR7/FR8",
         blocked_by=("FR10",)),
    Case("missing", "No payload (original cover)", "Payload Missing", "FR8",
         blocked_by=("FR10",)),
    Case("too_large", "Payload larger than cover capacity", "Rejected", "FR5/FR6"),
    Case("corrupt", "Corrupted / unreadable file", "Cannot Verify", "FR1/FR2"),
]


def _case_row(case: Case, result: RunResult | None, file=None, note="") -> dict:
    actual = result.outcome if result else "Error"
    pending = {s["fr"] for s in fr_status() if s["status"] != "done"}
    if actual == case.expected:
        verdict_ = "PASS"
    elif any(fr in pending for fr in case.blocked_by):
        verdict_ = "BLOCKED"
        note = note or f"needs {', '.join(case.blocked_by)} (pending)"
    else:
        verdict_ = "FAIL"
    return {"id": case.id, "case": case.title, "fr": case.fr, "expected": case.expected,
            "expected_polarity": polarity(case.expected), "actual": actual,
            "actual_polarity": polarity(actual),
            "provisional": bool(result and result.provisional), "result": verdict_,
            "note": note, "file": str(file) if file else None,
            "steps": [asdict(s) for s in result.steps] if result else [],
            "payload": result.payload if result else None}


def _edit_media_outside_payload(src, dst, kind):
    """Change high bits (not just LSBs) at the very end of the media."""
    if kind == "image":
        with Image.open(src) as im:
            im = im.convert("RGB")
        w, h = im.size
        px = im.load()
        for y in range(max(0, h - 8), h):
            for x in range(max(0, w - 8), w):
                r, g, b = px[x, y]
                px[x, y] = (r ^ 0xF0, g ^ 0xF0, b ^ 0xF0)
        im.save(dst, format="PNG")
    else:
        with wave.open(str(src), "rb") as wf:
            p = wf.getparams()
            raw = bytearray(wf.readframes(p.nframes))
        for i in range(max(0, len(raw) - 2000), len(raw)):
            raw[i] ^= 0x70
        with wave.open(str(dst), "wb") as wf:
            wf.setparams(p)
            wf.writeframes(bytes(raw))
    return dst


def run_case_suite(cover, params, messages=None, progress=None) -> dict:
    """Run every CASES entry against one cover. Returns {"rows", "summary", "evidence_dir"}.

    progress(i, total, text) is called before each case (for a progress bar)."""
    messages = {**MESSAGE_PRESETS, **(messages or {})}
    kind = detect_kind(cover)
    ext = ".png" if kind == "image" else ".wav"
    ev = Evidence("cases", kind)
    rows, stegos = [], {}
    total = len(CASES)
    report = lambda i, text: progress and progress(i, total, text)

    def verify_case(case, file, p=params, key=DEFAULT_PUBLIC_KEY, note=""):
        res = verify_core(file, p, key)
        rows.append(_case_row(case, res, file, note))

    for i, case in enumerate(CASES):
        report(i, case.title)
        try:
            if case.id.startswith("pos_"):
                name = case.id[4:]
                res = protect_core(cover, messages[name], params, out_path=ev.dir / f"stego_{name}")
                if res.outcome != "Protected":
                    rows.append(_case_row(case, res, cover, "protect step failed"))
                    continue
                stegos[name] = Path(res.outputs["stego"])
                verify_case(case, stegos[name])
            elif case.id == "too_large":
                info = inspect_media(cover)[1]
                cap = _capacity_bytes(kind, info["cover_size"], int(params.get("start", 0)),
                                      int(params["lsb_depth"]), params.get("low_byte_only"))
                big = "A" * (cap + 1024)
                res = protect_core(cover, big, params, out_path=ev.dir / "stego_too_large")
                rows.append(_case_row(case, res, cover, f"message of {len(big):,} chars"))
            elif case.id == "corrupt":
                bad = ev.dir / f"corrupt{ext}"
                bad.write_bytes(b"this is not a real media file")
                verify_case(case, bad)
            elif case.id == "missing":
                verify_case(case, cover)
            elif "short" not in stegos:
                rows.append(_case_row(case, None, None, "short-message stego was not created"))
            elif case.id == "tamper_payload":
                out = ev.dir / f"tampered_payload{ext}"
                start = _start_for(stegos["short"], params)
                if kind == "image":
                    image_stego.make_tampered_image(str(stegos["short"]), str(out), start,
                                                    int(params["lsb_depth"]))
                else:
                    audio_stego.make_tampered_audio(str(stegos["short"]), str(out), start,
                                                    int(params["lsb_depth"]),
                                                    bool(params.get("low_byte_only")))
                verify_case(case, out)
            elif case.id == "wrong_key":
                key_dir = ev.dir / "wrong_key"
                crypto_utils.generate_keypair(priv_path=str(key_dir / "private_key.pem"),
                                              pub_path=str(key_dir / "public_key.pem"))
                res = protect_core(cover, messages["short"], params,
                                   key_dir / "private_key.pem", ev.dir / "stego_wrong_key")
                if res.outcome != "Protected":
                    rows.append(_case_row(case, res, cover, "protect step failed"))
                else:
                    verify_case(case, res.outputs["stego"])
            elif case.id == "media_edit":
                out = _edit_media_outside_payload(stegos["short"], ev.dir / f"media_edited{ext}", kind)
                verify_case(case, out)
            elif case.id == "wrong_start":
                start = _start_for(stegos["short"], params)
                wrong = {**params, "start_mode": "manual", "start": start + 1}
                verify_case(case, stegos["short"], wrong, note=f"verified at {start + 1} "
                                                                f"instead of {start}")
        except Exception as exc:
            rows.append(_case_row(case, None, None, f"{type(exc).__name__}: {exc}"))
    report(total, "done")

    summary = {k: sum(1 for r in rows if r["result"] == k) for k in ("PASS", "FAIL", "BLOCKED")}
    summary["total"] = len(rows)
    ev.save_cases(rows, summary, cover, params)
    return {"rows": rows, "summary": summary, "evidence_dir": str(ev.dir), "kind": kind}


def _start_for(path, params) -> int:
    probe = RunResult("probe")
    start = _resolve_start(probe, inspect_media(path)[1]["cover_size"], params)
    return int(params.get("start", 0)) if start is None else start


# ---------- before / after comparison (FR11 visuals) ----------

def compare_media(cover, stego, diff_path=None) -> dict:
    kind = detect_kind(stego)
    if kind == "image":
        with Image.open(cover) as a, Image.open(stego) as b:
            a, b = a.convert("RGB"), b.convert("RGB")
        if a.size != b.size:
            return {"summary": "Cover and stego sizes differ; no comparison."}
        diff = ImageChops.difference(a, b)
        hist = diff.histogram()
        n = a.width * a.height * 3
        sq = sum(hist[c * 256 + v] * v * v for c in range(3) for v in range(256))
        changed_samples = n - sum(hist[c * 256] for c in range(3))
        r, g, bl = diff.split()
        mask = ImageChops.lighter(ImageChops.lighter(r, g), bl).point(lambda v: 255 if v else 0)
        changed_pixels = mask.histogram()[255]
        mse = sq / n
        psnr = float("inf") if mse == 0 else 10 * math.log10(255 ** 2 / mse)
        stats = {"changed_pixels": changed_pixels, "changed_samples": changed_samples,
                 "max_sample_change": max((v for v in range(256) for c in range(3)
                                           if hist[c * 256 + v]), default=0),
                 "psnr_db": None if math.isinf(psnr) else round(psnr, 2),
                 "change_bbox": mask.getbbox()}
        stats["summary"] = (f"{changed_pixels:,} of {a.width * a.height:,} pixels changed "
                            f"(max change {stats['max_sample_change']} per channel), "
                            f"PSNR {'inf' if stats['psnr_db'] is None else stats['psnr_db']} dB")
        if diff_path:
            stats["diff_image"] = str(_difference_overlay(a, mask, diff_path))
        return stats

    ca, pa = wav_samples(cover)
    cb, pb = wav_samples(stego)
    if len(ca) != len(cb):
        return {"summary": "Cover and stego lengths differ; no comparison."}
    changed = max_delta = 0
    noise = signal = 0
    for x, y in zip(ca, cb):
        d = y - x
        if d:
            changed += 1
            noise += d * d
            if abs(d) > max_delta:
                max_delta = abs(d)
        signal += x * x
    snr = None if noise == 0 else round(10 * math.log10(max(signal, 1) / noise), 2)
    return {"changed_samples": changed, "total_samples": len(ca), "max_sample_change": max_delta,
            "snr_db": snr,
            "summary": f"{changed:,} of {len(ca):,} samples changed (max change {max_delta} "
                       f"of +/-{2 ** (8 * pa.sampwidth - 1)}), SNR "
                       f"{'inf' if snr is None else snr} dB"}


def _difference_overlay(cover: Image.Image, mask: Image.Image, out, max_side=520):
    """Dimmed cover with changed pixels in red, downscaled so a 1-pixel change stays visible."""
    scale = min(1.0, max_side / max(cover.size))
    size = (max(1, int(cover.width * scale)), max(1, int(cover.height * scale)))
    base = ImageOps.grayscale(cover.resize(size, Image.BILINEAR)).point(lambda v: v // 3)
    small_mask = mask.resize(size, Image.BOX).point(lambda v: 255 if v else 0)
    overlay = Image.merge("RGB", (ImageChops.lighter(base, small_mask), base, base))
    overlay.save(out, format="PNG")
    return out


def wav_samples(path):
    """Return (samples as a flat list of signed ints, params)."""
    with wave.open(str(path), "rb") as wf:
        p = wf.getparams()
        raw = wf.readframes(p.nframes)
    if p.sampwidth == 1:
        return [b - 128 for b in raw], p
    if p.sampwidth in (2, 4):
        arr = array("h" if p.sampwidth == 2 else "i")
        arr.frombytes(raw[: len(raw) - len(raw) % p.sampwidth])
        if sys.byteorder == "big":
            arr.byteswap()
        return arr.tolist(), p
    return [int.from_bytes(raw[i:i + p.sampwidth], "little", signed=True)
            for i in range(0, len(raw) - p.sampwidth + 1, p.sampwidth)], p


def waveform_envelope(path, buckets=600) -> tuple[list, dict]:
    """(min, max) pairs normalised to -1..1 for drawing a waveform."""
    samples, p = wav_samples(path)
    peak = float(2 ** (8 * p.sampwidth - 1))
    step = max(1, len(samples) // buckets)
    env = []
    for i in range(0, len(samples), step):
        chunk = samples[i:i + step]
        env.append((min(chunk) / peak, max(chunk) / peak))
    return env, {"duration_s": p.nframes / p.framerate if p.framerate else 0}


# ---------- FR13 / FR7 innovation hooks ----------

def call_optional(fn, *args):
    """Returns (status, value): ok / pending / fail."""
    try:
        if is_stub(fn):
            raise NotImplementedError
        return STATUS_OK, fn(*args)
    except NotImplementedError:
        return STATUS_PENDING, f"{fn.__module__}.{fn.__name__}() is not implemented yet."
    except Exception as exc:
        return STATUS_FAIL, f"{type(exc).__name__}: {exc}"


def run_attack_simulation():
    return call_optional(verdict.run_attack_simulation)


def explain_start_location():
    return call_optional(start_location.explain_security)


def run_start_location_bias_demo(upper: int = 7, trials: int = 20_000):
    return call_optional(start_location.bias_demo, upper, trials)


def describe_start_location_bias_demo(result: dict) -> str:
    return start_location.describe_bias_demo(result)


# ---------- FR status board ----------

def fr_status() -> list[dict]:
    def st(*fns):
        return "done" if all(not is_stub(f) for f in fns) else "pending"

    fr9 = "done" if _stable_bytes_hook() else "partial"
    fr13_parts = [not is_stub(start_location.explain_security),
                  not is_stub(verdict.run_attack_simulation)]
    fr13 = "done" if all(fr13_parts) else "partial"
    return [
        {"fr": "FR1", "title": "Image input", "owner": "Person1", "status": st(image_stego.embed_image),
         "where": "image_stego.py"},
        {"fr": "FR2", "title": "Audio input", "owner": "Person2", "status": st(audio_stego.embed_audio),
         "where": "audio_stego.py"},
        {"fr": "FR3", "title": "Payload generation", "owner": "Person5",
         "status": st(crypto_utils.build_payload), "where": "crypto_utils.build_payload"},
        {"fr": "FR4", "title": "Digital signature", "owner": "Person5",
         "status": st(crypto_utils.sign_payload, crypto_utils.verify_signature),
         "where": "crypto_utils.sign_payload / verify_signature"},
        {"fr": "FR5", "title": "Image embedding", "owner": "Person1", "status": st(image_stego.embed_image),
         "where": "image_stego.embed_image"},
        {"fr": "FR6", "title": "Audio embedding", "owner": "Person2", "status": st(audio_stego.embed_audio),
         "where": "audio_stego.embed_audio"},
        {"fr": "FR7", "title": "Variable start location", "owner": "Person3",
         "status": st(start_location.derive_start_location),
         "where": "start_location.derive_start_location"},
        {"fr": "FR8", "title": "Extraction", "owner": "Person1/2",
         "status": st(image_stego.extract_image, audio_stego.extract_audio),
         "where": "extract_image / extract_audio"},
        {"fr": "FR9", "title": "Hash verification", "owner": "Person5", "status": fr9,
         "where": "crypto_utils.verify_hash + stable_cover_bytes (hook)"},
        {"fr": "FR10", "title": "Verdict generation", "owner": "Person4",
         "status": st(verdict.generate_verdict), "where": "verdict.generate_verdict"},
        {"fr": "FR11", "title": "Case demonstration (GUI)", "owner": "Person6", "status": "done",
         "where": "gui_app.py Test Cases tab"},
        {"fr": "FR12", "title": "Evidence & reproducibility", "owner": "Person6", "status": "done",
         "where": "tests/evidence/ (report.json + summary.md)"},
        {"fr": "FR13", "title": "Innovation", "owner": "Person3/4", "status": fr13,
         "where": "explain_security, run_attack_simulation, audio low_byte_only"},
    ]


# ---------- FR12: evidence folders ----------

def _safe_kind(path) -> str:
    try:
        return detect_kind(path)
    except ValueError:
        return "unknown"


def _file_record(path) -> dict:
    path = Path(path)
    rec = {"path": _rel(path)}
    if path.is_file():
        rec.update(sha256=crypto_utils.compute_hash(path.read_bytes()), bytes=path.stat().st_size)
    return rec


def _rel(path) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def environment() -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        commit = ""
    import Crypto
    import PIL
    return {"python": platform.python_version(), "platform": platform.platform(),
            "pillow": PIL.__version__, "pycryptodome": Crypto.__version__,
            "git_commit": commit or None, "generated": datetime.now().isoformat(timespec="seconds")}


class Evidence:
    """One timestamped folder per GUI run: report.json (machine) + summary.md (human)."""

    def __init__(self, action, kind):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = EVIDENCE_ROOT / f"{stamp}_{action}_{kind}"
        self.dir, n = base, 1
        while self.dir.exists():
            n += 1
            self.dir = base.with_name(f"{base.name}-{n}")
        self.dir.mkdir(parents=True)
        self.action, self.kind = action, kind

    def save_run(self, result: RunResult, inputs: dict, message=None):
        result.evidence_dir = str(self.dir)
        data = result.to_dict()
        data["inputs"] = {k: _file_record(v) for k, v in inputs.items()}
        data["outputs"] = {k: _file_record(v) for k, v in result.outputs.items()}
        data["environment"] = environment()
        if message is not None:
            data["message"] = message
        (self.dir / "report.json").write_text(json.dumps(data, indent=2, default=str))
        lines = [f"# {self.action.title()} -- {result.kind or self.kind}", "",
                 f"**Outcome:** {result.outcome}" + (" (provisional GUI verdict)" if result.provisional else "") + "  ",
                 f"**Generated:** {data['environment']['generated']}  ",
                 f"**Git commit:** {data['environment']['git_commit']}", "",
                 "## Inputs", ""]
        lines += [f"- {k}: `{v['path']}` sha256 `{v.get('sha256', 'n/a')}`" for k, v in data["inputs"].items()]
        lines += ["", "## Parameters", "", "```json", json.dumps(result.params, indent=2), "```",
                  "", "## Steps", "", "| FR | Step | Status | Detail |", "|---|---|---|---|"]
        lines += [f"| {s.fr} | {s.title} | {s.status.upper()} | {_md(s.detail)} |" for s in result.steps]
        if data["outputs"]:
            lines += ["", "## Outputs", ""]
            lines += [f"- {k}: `{v['path']}` sha256 `{v.get('sha256', 'n/a')}`"
                      for k, v in data["outputs"].items()]
        (self.dir / "summary.md").write_text("\n".join(lines) + "\n")

    def save_cases(self, rows, summary, cover, params):
        data = {"action": "cases", "kind": self.kind, "summary": summary,
                "cover": _file_record(cover), "params": params, "rows": rows,
                "environment": environment()}
        (self.dir / "report.json").write_text(json.dumps(data, indent=2, default=str))
        lines = [f"# Test case run -- {self.kind}", "",
                 f"**Cover:** `{_rel(cover)}`  ", f"**Parameters:** `{json.dumps(params)}`  ",
                 f"**Result:** {summary['PASS']} pass, {summary['FAIL']} fail, "
                 f"{summary['BLOCKED']} blocked of {summary['total']}  ",
                 f"**Generated:** {data['environment']['generated']}, git "
                 f"{data['environment']['git_commit']}", "",
                 "| Case | Type | Expected | Actual | Result | Note | File |",
                 "|---|---|---|---|---|---|---|"]
        for r in rows:
            actual = r["actual"] + (" *" if r["provisional"] else "")
            lines.append(f"| {r['case']} | {r['expected_polarity']} | {r['expected']} | {actual} | "
                         f"{r['result']} | {_md(r['note'])} | `{_rel(r['file']) if r['file'] else ''}` |")
        lines += ["", "\\* provisional GUI verdict -- verdict.generate_verdict() not implemented yet."]
        (self.dir / "summary.md").write_text("\n".join(lines) + "\n")


def _md(text) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", "<br>")


def list_evidence() -> list[dict]:
    runs = []
    if not EVIDENCE_ROOT.is_dir():
        return runs
    for d in sorted(EVIDENCE_ROOT.iterdir(), reverse=True):
        rep = d / "report.json"
        if not rep.is_file():
            continue
        try:
            data = json.loads(rep.read_text())
        except ValueError:
            continue
        if data.get("action") == "cases":
            s = data.get("summary", {})
            outcome = f"{s.get('PASS', 0)}/{s.get('total', 0)} pass, {s.get('BLOCKED', 0)} blocked"
        else:
            outcome = data.get("outcome", "")
        runs.append({"dir": str(d), "name": d.name, "action": data.get("action"),
                     "kind": data.get("kind"), "outcome": outcome,
                     "generated": data.get("environment", {}).get("generated", "")})
    return runs


def copy_file(src, dst) -> str:
    shutil.copyfile(src, dst)
    return str(dst)
