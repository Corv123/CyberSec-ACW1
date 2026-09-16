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

Person6 GUI skeleton:

```bash
python src/gui_app.py
```

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
│   ├── start_location.py    Person3
│   ├── verdict.py           Person4
│   └── gui_app.py           Person6
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
