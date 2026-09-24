# Test case run -- image

**Cover:** `samples\cover_image.png`  
**Parameters:** `{"start_mode": "manual", "start": 100, "seed": "", "lsb_depth": 2, "low_byte_only": false, "frame_step": 1, "use_dct": true}`  
**Result:** 8 pass, 2 fail, 0 blocked of 10  
**Generated:** 2026-09-23T19:05:19, git 72f74e3

| Case | Type | Expected | Actual | Result | Note | File |
|---|---|---|---|---|---|---|
| Authentic -- short message | positive | Authentic | Authentic | PASS |  | `tests\evidence\20260923-190435_cases_image\stego_short.png` |
| Authentic -- large message | positive | Authentic | Authentic | PASS |  | `tests\evidence\20260923-190435_cases_image\stego_large.png` |
| Authentic -- custom message | positive | Authentic | Authentic | PASS |  | `tests\evidence\20260923-190435_cases_image\stego_custom.png` |
| Tampered payload (one hidden bit flipped) | negative | Signature Invalid | Signature Invalid | PASS |  | `tests\evidence\20260923-190435_cases_image\tampered_payload.png` |
| Signed with a different private key | negative | Signature Invalid | Signature Invalid | PASS |  | `tests\evidence\20260923-190435_cases_image\stego_wrong_key.png` |
| Media edited outside the payload | negative | Tampered | Authentic | FAIL |  | `tests\evidence\20260923-190435_cases_image\media_edited.png` |
| Wrong start location (+1) | negative | Wrong Start Location | Wrong Start Location | PASS | verified at 101 instead of 100 | `tests\evidence\20260923-190435_cases_image\stego_short.png` |
| No payload (original cover) | negative | Payload Missing | Wrong Start Location | FAIL |  | `samples\cover_image.png` |
| Payload larger than cover capacity | negative | Rejected | Rejected | PASS | message of 188,511 chars | `samples\cover_image.png` |
| Corrupted / unreadable file | warning | Cannot Verify | Cannot Verify | PASS |  | `tests\evidence\20260923-190435_cases_image\corrupt.png` |

\* provisional GUI verdict -- verdict.generate_verdict() not implemented yet.
