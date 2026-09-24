# Verify -- image

**Outcome:** Authentic  
**Generated:** 2026-09-23T19:01:49  
**Git commit:** 72f74e3

## Inputs

- file: `tests\evidence\20260923-185837_protect_image\stego.png` sha256 `191b3cf72e2741c013aef17f18d80cf5bfc13e291c43dd8cacaf51817fa5b248`
- public_key: `keys\public_key.pem` sha256 `7dce210a0c57962d2ca6664a9d309a7b7b14e3f9c4330e3a4af298e2c8963c7d`

## Parameters

```json
{
  "start_mode": "manual",
  "start": 100,
  "seed": "",
  "lsb_depth": 2,
  "low_byte_only": false,
  "frame_step": 1,
  "use_dct": true,
  "start_location": 100
}
```

## Steps

| FR | Step | Status | Detail |
|---|---|---|---|
| FR1 | Load image input | OK | PNG image, 4000x4000 RGB, 48,000,000 colour samples |
| FR7 | Start location | INFO | Manual start location 100 (seed-derived mode not selected). |
| FR8 | Extract hidden blob from image (DCT) | OK | length header = 390 bytes<br>blob = 4 + 390 + 256 = 650 bytes<br>read from start 100 at depth 2 (DCT) |
| FR3 | Decode payload JSON | OK | All ALIGNMENT.md Section 4 fields present. |
| FR4 | Verify RSA signature | OK | Signature matches the payload and public key.<br>key: C:\Users\Jing Wen\SIT\Cyber Security Fundamentals (INF2005)\ACW1\Working Folder\CyberSec-ACW1\keys\public_key.pem |
| FR9 | Check cover hash | SKIP | DCT embedding changes spatial samples; FR9 LSB-plane stable hash does not apply. Authenticity rests on FR4 signature. |
| FR10 | Verdict (verdict.generate_verdict) | OK | Authentic |
