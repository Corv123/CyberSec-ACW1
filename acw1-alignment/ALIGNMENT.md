# ACW1 Team Alignment

**Steganographic Image & Audio Integrity Verification with Digital Signature-Based Authentication**
Repo: https://github.com/Corv123/CyberSec-ACW1

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

| Decision | Choice | Owner |
|---|---|---|
| Language | Python 3.10+ | All |
| Image library | Pillow (PIL) | Person1 |
| Audio library | Python's built-in `wave` module | Person2 |
| Crypto library | `pycryptodome` | Person5 |
| Hash algorithm | SHA-256 | Person5 |
| Signature scheme | RSA-2048, PKCS#1 v1.5 | Person5 |
| GUI framework | Tkinter (built-in, zero install) | Person6 |
| Payload serialization | JSON → UTF-8 bytes | Person5 |
| Image cover format | PNG only (JPEG compression destroys LSB data) | Person1 |
| Audio cover format | WAV / PCM only | Person2 |

---

## 4. Payload schema and wire format

**Payload (JSON, built by `crypto_utils.build_payload`):**

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

---

## 5. Per-person responsibilities

### Person1 — Image Steganography (FR1, FR5, FR8)
**Builds:** PNG input validation, LSB embed/extract across RGB channels with adjustable depth (1–8), capacity check.
**Depends on:** `crypto_utils.pack()/unpack()` for the byte format, `start_location.derive_start_location()` for where to begin.
**Hands off to:** Person6 (GUI calls your functions), Person4 (verdict engine consumes your extract output).
**File:** `src/image_stego.py` — `embed_image()`, `extract_image()`, `check_capacity()`.

### Person2 — Audio Steganography (FR2, FR6, FR8)
**Builds:** WAV/PCM input validation, LSB embed/extract across samples, capacity check. Same shape as Person1's work, applied to a 1D sample array instead of pixels.
**Depends on / hands off to:** same as Person1.
**File:** `src/audio_stego.py` — `embed_audio()`, `extract_audio()`, `check_capacity()`.

### Person3 — Start Location & Innovation (FR7, FR13)
**Builds:** the scheme for deriving where embedding starts (suggested innovation: a keyed PRNG rather than a fixed/guessable location), plus the write-up on why it resists guessing.
**Depends on:** needs to agree the seed/key format with Person5 — reuse the shared keypair, or a separate shared secret? (see open decisions below).
**Hands off to:** Person1 and Person2 both call your location function directly.
**File:** `src/start_location.py` — `derive_start_location()`.

### Person4 — Verification & Innovation (FR10, FR13)
**Builds:** the verdict engine (takes signature/hash results from Person5 plus extraction success from Person1/2, returns one of the six verdicts), plus an attack-simulation module (suggested innovation) that runs the negative cases automatically.
**Depends on:** `crypto_utils.verify_signature()` / `verify_hash()`, Person1/2's extract functions.
**File:** `src/verdict.py` — `generate_verdict()`, `run_attack_simulation()`.

### Person5 — Security & Cryptography (FR3, FR4, FR9) — you
**Builds:** payload construction, signing, hash verification.
**Hands off to:** everyone — this is the shared contract the rest of the team codes against.
**File:** `src/crypto_utils.py` — already implemented and runnable, see the starter kit.

### Person6 — GUI, Integration & Testing (FR11, FR12)
**Builds:** the Tkinter GUI wiring every module together (file pickers, LSB-depth selector, start-location display, before/after preview, embed/extract/verify buttons), generates tampered files for negative cases (with Person1/2), collects test evidence, writes the final README.
**File:** `src/gui_app.py` — skeleton provided, real wiring TODO.

---

## 6. Build order — don't start all six in parallel on day one

- **Phase 0 (one shared meeting):** confirm this document. Person5 shares the crypto module. Person3 locks the start-location approach with Person1/Person2. Person6 scaffolds the GUI skeleton. Nobody writes real embed/extract logic yet.
- **Phase 1:** Person1 and Person2 build embedding, in parallel with each other, against Person5's payload format and Person3's start-location function.
- **Phase 2:** Person1/Person2 build extraction. Person4 builds the verdict engine.
- **Phase 3:** Person6 wires everything into the real GUI and works with Person1/Person2 to generate tampered/negative-case files.
- **Phase 4:** full team dry run of the 25-minute demo; everyone rehearses explaining their own FR area.

---

## 7. Test data

- **Short message:** one Learning Outcome from the spec (team to pick which one — see open decisions)
- **Large message:** the Project Overview paragraph, copied verbatim from the assignment spec
- **Custom message:** team-defined scenario (see open decisions)

---

## 8. Deadlines

| Item | Due |
|---|---|
| Demo plan, Declaration of Originality, Contribution statement | 1 day before your demo slot |
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
├── keys/                    RSA keypair (committed — demo-only, not secret per spec Section 9)
├── samples/                 cover / stego / tampered files
└── tests/                   screenshots, logs, test evidence
```

---

## 10. Open decisions — need team input

- [ ] GUI framework: confirm Tkinter, or does the team prefer a web UI instead?
- [ ] Who owns the "Limitations, ethics and AI-use reflection" section (2 marks) — currently nobody has it.
- [ ] Which Learning Outcome is the short test message?
- [ ] What's the custom payload scenario for the third test case?
- [ ] Person3: exact start-location derivation method and what seed/key it uses.
- [ ] Person4: exact attack-simulation scenarios to implement.
- [ ] Actual source images/audio to use as cover files (any PNG/WAV works — team to pick or create some).

---

## 11. Reminder

5 of the 40 marks are individual. You need to be able to explain your own FR area in the live demo — even for code a teammate wrote that you're calling into. Understand it, don't just import it.
