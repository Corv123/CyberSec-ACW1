# CyberSec ACW1 -- Steganographic Image & Audio Verification

Team project for INF2005 ACW1. Full shared decisions live in [ALIGNMENT.md](ALIGNMENT.md).

## Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Quick checks

Person5 crypto:

```bash
python src/crypto_utils.py
```

Person1 image (positive: embed + extract + signature):

```bash
python src/image_stego.py
```

Person1 negative sample only (writes tampered PNG):

```bash
python src/image_stego.py --tamper
```

Person6 GUI (Tkinter, no extra install):

```bash
python src/gui_app.py
```

Tabs: **Protect** (FR1-FR7, FR9) · **Verify** (FR8-FR10) · **Test Cases** (FR11, all
positive + negative cases in one click) · **Innovation** (FR13). Every run is saved to
`tests/evidence/<time>_<action>_<media>/` as
`report.json` (params, steps, SHA-256 of every file, environment, git commit) and
`summary.md` (paste-ready table). An image test-case run writes ~50 MB of PNGs, so
commit only the runs you need as evidence.

### How FRs connect (end-to-end)

`gui_pipeline.protect_core` / `verify_core` wire every FR into one path:

1. **FR1/FR2** (+ video OPT) — detect cover kind and size  
2. **FR7** — resolve start (`manual` or `derive_start_location`)  
3. **FR9** — hash stable non-LSB cover bytes (`stable_cover_bytes`; skipped for DCT)  
4. **FR3/FR4** — build JSON payload + RSA-2048 sign → pack `4|N|256` blob  
5. **FR5/FR6** (+ DCT/video OPT) — capacity check + embed  
6. **FR8** — extract blob on verify  
7. **FR4/FR9/FR10** — verify signature, re-check cover hash, `generate_verdict`  
8. **FR11/FR12** — Cases tab + evidence folders  
9. **FR13** — Innovation tab / `run_attack_simulation`

Smoke: `python tests/_integration_smoke.py`

## Structure

```
/
├── ALIGNMENT.md
├── README.md
├── requirements.txt
├── payload_example.json
├── instruction.txt
├── src/
│   ├── crypto_utils.py      Person5
│   ├── image_stego.py       Person1  (embed / extract / tamper helper)
│   ├── audio_stego.py       Person2
│   ├── video_stego.py       Optional video cover (same LSB + blob contract)
│   ├── dct_image_stego.py   Optional DCT-domain image stego (alt. to LSB)
│   ├── start_location.py    Person3
│   ├── verdict.py           Person4
│   ├── gui_app.py           Person6  (Tkinter app: tabs)
│   ├── gui_components.py    Person6  (reusable widgets)
│   └── gui_pipeline.py      Person6  (wiring + evidence, no Tk)
├── keys/                    RSA keypair (demo)
├── samples/                 cover / stego / tampered
└── tests/                   evidence
```

## Samples (agreed names)

| File | Role |
|------|------|
| `samples/cover_image.png` | Cover (from Earth Day) |
| `samples/Earth_Day.png` / `Earth_Planet.png` | Extra covers |
| `samples/stego_image_short.png` | From `python src/image_stego.py` |
| `samples/stego_image_tampered.png` | From `python src/image_stego.py --tamper` |
| `samples/cover_video.avi` | Synthetic video cover (optional) |
| `samples/stego_video_short.avi` | From `python src/video_stego.py` |
| `samples/stego_video_tampered.avi` | From `python src/video_stego.py --tamper` |

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

## Person1 API (for GUI / verdict / crypto wiring)

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

## Person3 API (start location)

```python
from start_location import derive_start_location, explain_security, bias_demo, describe_bias_demo

start = derive_start_location(cover_size, seed.encode("utf-8"))  # 0 <= start < cover_size, deterministic
print(explain_security())  # FR13 write-up: PBKDF2-HMAC-SHA256 stretch + rejection sampling

result = bias_demo(upper=7, trials=20_000)  # chi-square evidence: rejection sampling vs naive modulo
print(describe_bias_demo(result))
```

`seed` is whatever passphrase the GUI's "Derive from seed (FR7)" field holds (UTF-8
bytes); `cover_size` is `w*h*3` (image) or `nframes*nchannels*sampwidth` (audio), same
as everywhere else in the pipeline. Same seed + same cover_size always reproduces the
same start location -- that's what lets Verify find the payload without the location
ever being transmitted. See the **Innovation** tab in the GUI for the live version of
`explain_security()` and `bias_demo()`.

## Person6 GUI API (for plugging in your FR)

The GUI detects unfinished functions (body is only `raise NotImplementedError`) and
shows them as **PENDING**. Implement your function and the GUI uses it on the next
run -- no GUI change needed.

| Owner | Implement | GUI effect |
|---|---|---|
| Person3 | ✅ `start_location.derive_start_location(cover_size, seed)` | "Derive from seed (FR7)" option works; `cover_size` = w*h*3 (image) or nframes*nchannels*sampwidth (audio) |
| Person3 | ✅ `start_location.explain_security()` -> `str` | Shown on the **Innovation** tab, alongside a live `bias_demo()` chi-square comparison |
| Person4 | `verdict.generate_verdict(extraction_successful, signature_valid, hash_valid)` | Replaces the provisional verdict (marked `*`). `hash_valid` may be `None`. Add a `context=None` keyword to also receive extraction error, printable ratio, start location, etc. |
| Person4 | `verdict.run_attack_simulation()` -> list of dicts or `str` | Would show on the **Innovation** tab (no widget wired in yet); available now via `gui_pipeline.run_attack_simulation()`, render with `gui_components.DataTable` |
| Person5 | *(new, optional)* `crypto_utils.stable_cover_bytes(path, cover_type, lsb_depth)` -> `bytes` | Used for `cover_hash` on protect and checked on verify (FR9); unblocks the "media edited" test case |

Call the pipeline without the GUI:

```python
from gui_pipeline import protect, verify, run_case_suite, default_params
r = verify("samples/stego_image_short.png", default_params(start=100, lsb_depth=2))
print(r.outcome, r.provisional, [(s.fr, s.status) for s in r.steps])
```

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
