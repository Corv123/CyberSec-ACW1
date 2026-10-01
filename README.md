# CyberSec ACW1 -- Steganographic Image & Audio Verification

Team project for INF2005 ACW1. Full shared decisions live in [ALIGNMENT.md](ALIGNMENT.md).

## Requirements

| Dependency | Version tested | Used for |
|---|---|---|
| Python | **3.10 or newer** (tested on 3.13) | everything |
| Tkinter | 8.6 (ships with the python.org installer) | GUI |
| `pillow` | 11.1 | image load/save |
| `pycryptodome` | 3.23 | RSA-2048 signing, SHA-256 |
| `numpy` | 2.2 | DCT + video sample arrays |
| `opencv-python-headless` | 4.13 (plain `opencv-python` also works) | DCT, video I/O |

Everything else (`hashlib`, `hmac`, `wave`, `json`) is Python standard library.

## Setup

Run from the repo root (the folder containing this README).

**Windows (PowerShell):**

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**macOS / Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Check it worked:

```bash
python -c "import PIL, Crypto, numpy, cv2, tkinter; print('ok')"
```

Expected output: `ok`

**Keys:** `keys/private_key.pem` and `keys/public_key.pem` are already committed and
shared by the whole team. **Do not run `python src/crypto_utils.py` unless you mean
to replace them**: it generates a new keypair, and every existing stego file then
fails with *Signature Invalid*.

## Run the app

```bash
python src/gui_app.py
```

Expected: a window with four tabs. It opens at 1320x900 when the screen has room;
on smaller (or display-scaled) laptop screens it opens maximised, and each tab gets a
scrollbar instead of being squashed. Scroll down to reach the buttons at the bottom of
the left column.

| Tab | FRs | What to do |
|---|---|---|
| **Protect** | FR1-FR7, FR9 | Pick a cover (`samples/cover_image.png` or `samples/cover_audio.wav`), type a message, choose a start mode, click Protect. Shows each FR step and writes the stego file. |
| **Verify** | FR8-FR10 | Pick a stego file, use the **same** start mode / seed / LSB depth as Protect. Shows each step and one of six verdicts: Authentic, Tampered, Signature Invalid, Payload Missing, Wrong Start Location, Cannot Verify. |
| **Test Cases** | FR11 | **Browse** for a cover first (the pre-filled `file_example_WAV_1MG.wav` is not in the repo; use `samples/cover_audio.wav` for a run of a few seconds), then click **Run all test cases**. Runs 3 positive + 7 negative cases. Expected: every row PASS. |
| **Innovation** | FR13 | Start-location write-up and chi-square bias demo; attack simulation. |

Start modes: **Manual** (type a start index) or **Derive from seed (FR7)** (type a
passphrase; the start location and an encryption key are derived from it, and an empty
seed is rejected). Verify with the wrong seed gives *Payload Missing*.

Other embedding options (Protect and Verify must use the same values):
**LSB depth** 1-8 (default 2), **Audio: low byte only** (less distortion, half the
capacity), **Image: use DCT embedding** (optional, mid-band 8x8 coefficients), and
**Video frame step** (optional; `.avi` covers only).

Every GUI run saves `tests/evidence/<time>_<action>_<media>/` containing `report.json`
(parameters, steps, SHA-256 of every file, environment, git commit; the seed is
stored as `<redacted>`) and `summary.md` (a table ready to paste into the report). An
image test-case run writes ~50 MB of PNGs, so only commit the runs you need.

## Command-line self-tests

Each module can be run on its own from the repo root. All of them use the committed
keys and the covers in `samples/`.

| Command | What it checks | Expected output ends with | Writes |
|---|---|---|---|
| `python src/image_stego.py` | FR1/FR5/FR8: embed, extract and verify the signature on an image | `PASS: image embed/extract + signature OK` | `samples/stego_image_short.png` |
| `python src/image_stego.py --tamper` | negative sample: flips one hidden bit | `Generated negative sample (tamper only)` | `samples/stego_image_tampered.png` |
| `python src/audio_stego.py` | FR2/FR6/FR8: the same for WAV audio | `PASS: audio embed/extract + signature OK` | `samples/stego_audio_short.wav` |
| `python src/audio_stego.py --tamper` | negative audio sample | `Generated negative sample (tamper only)` | `samples/stego_audio_tampered.wav` |
| `python src/start_location.py` | FR7/FR13: determinism, range, seed sensitivity, wrong seed, empty-seed rejection, encryption round trip, uniformity (chi-square), timing; then prints the Innovation tab write-up | `PASS: start_location self-test OK` | nothing |
| `python src/verdict.py` | FR10/FR13: 10 attack scenarios, each giving its expected verdict | `PASS: all 10 scenarios produced the expected verdict.` | temp files only |
| `python src/dct_image_stego.py` | optional DCT-domain image embedding | `PASS: DCT embed/extract + signature OK` | `samples/stego_dct_short.png` |
| `python src/video_stego.py` | optional lossless-AVI video embedding | `PASS: video embed/extract + signature OK` | `samples/cover_video_selftest.avi`, `samples/stego_video_short.avi` |

Example (`python src/image_stego.py`):

```
Capacity check
  start_location=100, lsb_depth=2
  total_embed_size=573
  fits: True
...
FR8 - Extracted full blob + crypto verify
  blob_match: True
  signature_valid: True

PASS: image embed/extract + signature OK
```

Byte counts change slightly per run (the payload contains a timestamp and a nonce).
Any line starting `FAIL`, or a Python traceback, means something is broken.

### How the FRs connect (end-to-end)

`gui_pipeline.protect_core` / `verify_core` run every FR in one path:

1. **FR1/FR2** (+ optional video) - detect cover kind and size
2. **FR7** - resolve the start (manual, or derived from the seed + blob encryption key)
3. **FR9** - hash the stable (non-LSB) cover bytes (skipped for DCT)
4. **FR3/FR4** - build the JSON payload, RSA-2048 sign it, pack the `4|N|256` blob (encrypted in seed mode)
5. **FR5/FR6** (+ optional DCT/video) - capacity check, embed
6. **FR8** - extract the blob on verify (decrypted in seed mode)
7. **FR4/FR9/FR10** - verify the signature, re-check the cover hash, `generate_verdict`
8. **FR11/FR12** - Test Cases tab, evidence folders
9. **FR13** - Innovation tab (start-location security, attack simulation)

## Structure

```
/
├── ALIGNMENT.md             shared team decisions
├── README.md
├── requirements.txt
├── payload_example.json     example of the signed JSON payload
├── src/
│   ├── crypto_utils.py      Jing Wen  (payload, RSA sign/verify, pack/unpack, cover hash)
│   ├── image_stego.py       Corvan  (embed / extract / tamper helper)
│   ├── audio_stego.py       Jeanie
│   ├── start_location.py    Shannon  (seed -> start location + blob encryption)
│   ├── verdict.py           Venecia  (six verdicts + attack simulation)
│   ├── gui_app.py           Karthik  (Tkinter app: tabs)
│   ├── gui_components.py    Karthik  (reusable widgets)
│   ├── gui_pipeline.py      Karthik  (wiring + evidence, no Tk)
│   ├── video_stego.py       optional video cover (same LSB + blob contract)
│   └── dct_image_stego.py   optional DCT-domain image stego (alternative to LSB)
├── keys/                    shared RSA keypair (demo only)
├── samples/                 covers, stego and tampered files
└── tests/evidence/          saved GUI runs (FR12)
```

## Samples

| File | Role |
|------|------|
| `samples/cover_image.png` | Image cover |
| `samples/cover_audio.wav` | Audio cover |
| `samples/stego_audio_short.wav` | Audio stego (from `python src/audio_stego.py`: manual start 500, LSB 2) |
| `samples/stego_audio_tampered.wav` | Tampered audio (from `python src/audio_stego.py --tamper`) |
| `samples/background.png`, `cat.png`, `test67.png`, `stego_updated_variable_startloc.png` | Extra test images |
| `samples/stego_image_short.png`, `stego_image_tampered.png` | Created by `python src/image_stego.py` (`--tamper`) |
| `samples/stego_dct_short.png` | Created by `python src/dct_image_stego.py` |
| `samples/cover_video_selftest.avi`, `stego_video_short.avi` | Created by `python src/video_stego.py` |

## Optional video API

Same shape as image/audio. Stego is written as **lossless AVI** (LSB-safe).

```bash
python src/video_stego.py
python src/video_stego.py --tamper
```

```python
from video_stego import check_capacity, embed_video, extract_video, make_tampered_video
embed_video(cover, blob, start_location, lsb_depth, output_path, frame_step=1)
blob = extract_video(stego, start_location, lsb_depth, frame_step=1)
```

`frame_step=1` uses every frame; `frame_step=2` is selected-frame embedding (every 2nd frame).

## Corvan API (for GUI / verdict / crypto wiring)

```python
from image_stego import (
    check_capacity,
    embed_image,
    extract_image,
    make_tampered_image,
)

# blob = crypto_utils.pack(payload_bytes, signature)
embed_image(cover, blob, start_location, lsb_depth, output_path)
blob = extract_image(stego, start_location, lsb_depth)  # full 4+N+256
make_tampered_image(stego, tampered_out, start_location, lsb_depth)
```

Indexing: flat RGB sample index. Wire framing owned by `crypto_utils`, not image_stego.

## Shannon API (start location)

```python
from start_location import derive_secrets, apply_mask, explain_security, bias_demo, describe_bias_demo

start, key = derive_secrets(cover_size, seed.encode("utf-8"))  # one PBKDF2 run; empty seed -> ValueError
enc_blob = apply_mask(blob, key)                   # XOR-encrypt header+payload+signature (self-inverse)
blob = extract_image(stego, start, lsb, unmask=lambda d: apply_mask(d, key))
print(explain_security())  # FR13 write-up: method, how Verify finds it, limitations

result = bias_demo(upper=7, trials=20_000)  # chi-square evidence: rejection sampling vs naive modulo
print(describe_bias_demo(result))
```

`seed` is whatever passphrase the GUI's "Derive from seed (FR7)" field holds (UTF-8
bytes); `cover_size` is `w*h*3` (image) or `nframes*nchannels*sampwidth` (audio), same
as everywhere else in the pipeline. Same seed + same cover_size always reproduces the
same start location and key -- that's what lets Verify find the payload without the
location ever being transmitted. In derive mode the whole blob is encrypted, so a
wrong seed reads as random bits and gives **Payload Missing** (manual mode still
demonstrates **Wrong Start Location**). All `extract_*` functions take an optional
`unmask=` callback; embed functions are unchanged (the pipeline encrypts first).
The seed is written to evidence reports as `<redacted>`. See the **Innovation** tab
in the GUI for the live version of `explain_security()` and `bias_demo()`.

## Karthik GUI API (for plugging in your FR)

The GUI detects unfinished functions (body is only `raise NotImplementedError`) and
shows them as **PENDING**. All functions below are now implemented, so nothing should
show as PENDING.

| Owner | Implement | GUI effect |
|---|---|---|
| Shannon | ✅ `start_location.derive_secrets(cover_size, seed)` / `apply_mask` | "Derive from seed (FR7)" option: start location + blob encryption; `cover_size` = w*h*3 (image) or nframes*nchannels*sampwidth (audio) |
| Shannon | ✅ `start_location.explain_security()` -> `str` | Shown on the **Innovation** tab, alongside a live `bias_demo()` chi-square comparison |
| Venecia | ✅ `verdict.generate_verdict(extraction_successful, signature_valid, hash_valid, context=None)` | Gives the FR10 verdict on Verify and in Test Cases. `hash_valid` may be `None`; `context` carries extraction error, printable ratio, start location, etc. |
| Venecia | ✅ `verdict.run_attack_simulation()` -> list of dicts | **Run attack simulation** button on the **Innovation** tab (also `python src/verdict.py`) |
| Jing Wen | ✅ `crypto_utils.stable_cover_bytes(path, cover_type, lsb_depth)` -> `bytes` | Used for `cover_hash` on protect and checked on verify (FR9); drives the "media edited" test case |

Call the pipeline without the GUI (from the repo root):

```python
import sys; sys.path.insert(0, "src")
from gui_pipeline import protect, verify, default_params
p = default_params(start_mode="derive", seed="my-passphrase", lsb_depth=2)
r = protect("samples/cover_image.png", "hello", p)
v = verify(r.outputs["stego"], p)
print(r.outcome, v.outcome)   # expected: Protected Authentic
```

Both calls write an evidence folder under `tests/evidence/`, exactly like the GUI.

Note: stego files made by the `image_stego.py` / `audio_stego.py` self-tests use a
placeholder cover hash (SHA-256 of the whole cover file). The GUI and pipeline check a
hash of the *stable* cover bytes (FR9), so verifying a self-test file there reports
**Tampered**. Make demo stego files with the **Protect** tab (or `protect()`) instead.

Reuse a widget in your own window:

```python
from gui_components import VerdictBanner, StepList, CaseTable, DataTable, MediaPreview
banner.show("Tampered")            # red NEGATIVE CASE banner
steps.set_steps(result.steps)       # per-FR PASS / FAIL / PENDING with detail
table.set_rows(rows)                # expected vs actual test-case table
```

Test cases live in `gui_pipeline.CASES`; message presets (short/large/custom,
ALIGNMENT.md Section 7) in `gui_pipeline.MESSAGE_PRESETS` -- replace the placeholder
texts with the chosen Learning Outcome and the spec's Project Overview.
