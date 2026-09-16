# CyberSec ACW1 -- Steganographic Image & Audio Verification

Team project for INF2005 ACW1. Full spec decisions and per-person responsibilities
live in [ALIGNMENT.md](ALIGNMENT.md) -- read that first.

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Quick check

Person5's crypto module is runnable standalone:

```bash
python src/crypto_utils.py
```

This generates a keypair into `keys/`, builds and signs a test payload, and
verifies it -- if it prints `Signature valid: True`, your environment is set up
correctly.

Person6's GUI skeleton also runs as-is (does nothing real yet):

```bash
python src/gui_app.py
```

## Structure

See ALIGNMENT.md Section 9 for the full folder layout and who owns each file.

## Deadlines

- Demo plan, Declaration of Originality, Contribution statement: 1 day before demo
- Source code, this README, sample files, test evidence, keys: Week 5 Friday
- Live demo: Week 5 lab slot, 25 min, all 6 members speaking
