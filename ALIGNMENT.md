# ACW1 Team Alignment

**Steganographic Image & Audio Integrity Verification with Digital Signature-Based Authentication**
Repo: [https://github.com/Corv123/CyberSec-ACW1](https://github.com/Corv123/CyberSec-ACW1)

This is the single shared reference for the whole team. If your code disagrees with this doc, either the code's wrong or the doc needs updating — flag it to the team, don't just quietly diverge.

---

## 1. What we're building

A GUI tool that hides a signed, hashed verification payload inside an image and an audio file (LSB replacement), then extracts and checks it, returning one of six verdicts: **Authentic, Tampered, Signature Invalid, Payload Missing, Wrong Start Location, Cannot Verify.**

---



## 2. The pipeline

**Protect (sender) side:**

```
Cover file → Build & sign payload (Person5) → Embed at start location (Person1/Person2) → Stego file
```

**Verify (receiver) side:**

```
Stego file → Extract payload & signature (Person1/Person2) → Check signature & hash (Person5) → Verdict (Person4)
```

Person3's start-location design plugs into both the embed step and the extract step, on either side.

---



## 3. Locked decisions (defaults — flag in team chat if anyone wants to change one)


| Decision              | Choice                                        | Owner   |
| --------------------- | --------------------------------------------- | ------- |
| Language              | Python 3.10+                                  | All     |
| Image library         | Pillow (PIL)                                  | Person1 |
| Audio library         | Python's built-in `wave` module               | Person2 |
| Crypto library        | `pycryptodome`                                | Person5 |
| Hash algorithm        | SHA-256                                       | Person5 |
| Signature scheme      | RSA-2048, PKCS#1 v1.5                         | Person5 |
| GUI framework         | Tkinter (built-in, zero install)              | Person6 |
| Payload serialization | JSON → UTF-8 bytes                            | Person5 |
| Image cover format    | PNG only (JPEG compression destroys LSB data) | Person1 |
| Audio cover format    | WAV / PCM only                                | Person2 |


---



## 4. Payload schema and wire format

**Payload (JSON, built by** `crypto_utils.build_payload`**):**

```json
{
  "media_id": "IMG-0001",
  "timestamp": "2026-09-12T10:15:00+00:00",
  "cover_type": "image",
  "cover_hash": "sha256 hex digest of the stable part of the cover",
  "nonce": "16 random bytes, hex — blocks replay of an old stego file",
  "message": "the secret content being hidden — this is what varies for the short/large/custom test cases",
  "metadata": { "team": "P1-4", "lsb_depth": 2 }
}
```

**Important:** `cover_hash` must NOT be a hash of the whole stego file — embedding changes LSBs, so that hash would never match on decode. Hash only the part of the cover your embedding never touches (e.g. everything except the LSB plane in use).

**What actually gets embedded (the "blob"):**

```
[4-byte big-endian length header][JSON payload bytes][256-byte RSA-2048 signature]
```

The length header tells the decoder how many payload bytes to read before the signature starts. `crypto_utils.pack()` / `unpack()` handle this — everyone else just passes the resulting bytes to their embed/extract functions.

**Extract size rule (Person1/Person2):** read **4 + N + 256** bytes from the cover (N from the length header). Do not stop after the payload.

---

## 5. Per-person responsibilities

### Person1 — Image Steganography (FR1, FR5, FR8)
**Builds:** PNG input validation, LSB embed/extract across RGB channels with adjustable depth (1–8), capacity check.
**Depends on:** `crypto_utils.pack()/unpack()` for the byte format, `start_location.derive_start_location()` for where to begin.
**Hands off to:** Person6 (GUI calls your functions), Person4 (verdict engine consumes your extract output).
**File:** `src/image_stego.py` — `embed_image()`, `extract_image()`, `check_capacity()`.
**Status:** Implemented (flat RGB sample index). Self-test: `python src/image_stego.py` and `python src/image_stego.py --tamper`. API: `embed_image`, `extract_image`, `check_capacity`, `make_tampered_image`.

### Person2 — Audio Steganography (FR2, FR6, FR8)
**Builds:** WAV/PCM input validation, LSB embed/extract across samples, capacity check. Same shape as Person1.
**File:** `src/audio_stego.py` — `embed_audio()`, `extract_audio()`, `check_capacity()`.

### Person3 — Start Location & Innovation (FR7, FR13)
**Builds:** scheme for deriving where embedding starts; encoder/decoder must agree.
**File:** `src/start_location.py` — `derive_start_location()`.

### Person4 — Verification & Innovation (FR10, FR13)
**Builds:** verdict engine + optional attack-simulation module.
**File:** `src/verdict.py` — `generate_verdict()`, `run_attack_simulation()`.

### Person5 — Security & Cryptography (FR3, FR4, FR9)
**Builds:** payload construction, signing, hash verification, pack/unpack.
**File:** `src/crypto_utils.py` — implemented and runnable.

### Person6 — GUI, Integration & Testing (FR11, FR12)
**Builds:** Tkinter GUI, demos/evidence, sample packaging.
**File:** `src/gui_app.py` — skeleton provided.

---

## 6. Build order

- **Phase 0:** confirm this document; Person5 crypto shared; Person3 start-location approach; Person6 GUI skeleton.
- **Phase 1:** Person1 and Person2 embedding against Person5 blob format and Person3 start location.
- **Phase 2:** Person1/Person2 extraction; Person4 verdict engine.
- **Phase 3:** Person6 wires GUI; generate tampered/negative-case files with Person1/2.
- **Phase 4:** full team dry run of the 25-minute demo.

---

## 7. Test data

- **Short message:** one Learning Outcome from the spec (team to pick).
- **Large message:** Project Overview paragraph from the assignment spec.
- **Custom message:** team-defined scenario.

---

## 8. Deadlines

| Item | Due |
|---|---|
| Demo plan, Declaration of Originality, Contribution statement | 1 day before demo slot |
| Source code, README, sample files, test evidence, keys | Week 5, Friday |
| Live demo (25 min, all 6 members speaking) | Week 5 lab slot |

---

## 9. Repo structure

```
/
├── ALIGNMENT.md
├── README.md
├── requirements.txt
├── payload_example.json
├── src/
│   ├── crypto_utils.py      Person5
│   ├── image_stego.py       Person1
│   ├── audio_stego.py       Person2
│   ├── start_location.py    Person3
│   ├── verdict.py           Person4
│   └── gui_app.py           Person6
├── keys/
├── samples/
└── tests/
```

---

## 10. Open decisions — need team input

- [ ] GUI framework: confirm Tkinter, or web UI?
- [ ] Who owns the "Limitations, ethics and AI-use reflection" section?
- [ ] Which Learning Outcome is the short test message?
- [ ] Custom payload scenario for the third test case?
- [ ] Person3: exact start-location method and seed/key source.
- [ ] Person4: exact attack-simulation scenarios.
- [ ] Confirm primary cover files (`samples/cover_image.png` is Earth Day for now).
- [x] Person5: `cover_hash` over stable non-LSB bytes via `crypto_utils.stable_cover_bytes()` (image / audio / video). DCT mode skips FR9 match (spatial rewrite).
- [x] Optional video cover: `src/video_stego.py` (frame LSB, same pack/unpack blob; GUI Protect/Verify/Cases accept AVI/MP4).

---

## 11. Reminder

5 of the 40 marks are individual. Explain your own FR area in the live demo.

