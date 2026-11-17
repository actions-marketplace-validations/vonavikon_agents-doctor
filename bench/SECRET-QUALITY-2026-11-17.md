# Secret detection quality benchmark

Date: 2026-11-17 16:19

## Headline metrics

| metric | value |
|---|---|
| true positives | 40 |
| false positives | 0 |
| false negatives | 0 |
| true negatives | 29 |
| precision | 1.000 |
| recall | 1.000 |
| false positive rate | 0.000 |
| false negative rate | 0.000 |

Floors: precision >= 0.95, recall >= 0.95.

## Per-rule recall

| rule | tp | fn |
|---|---|---|
| SEC-001 | 3 | 0 |
| SEC-002 | 4 | 0 |
| SEC-003 | 3 | 0 |
| SEC-004 | 3 | 0 |
| SEC-005 | 6 | 0 |
| SEC-101 | 2 | 0 |
| SEC-102 | 3 | 0 |
| SEC-103 | 3 | 0 |
| SEC-104 | 3 | 0 |
| SEC-105 | 4 | 0 |
| SEC-106 | 3 | 0 |
| SEC-107 | 3 | 0 |

## Adversarial shapes (documented misses, not failures)

Detected 0 of 4. These are counted separately: detection here is a bonus, missing them is documented behaviour (obfuscation defeats literal rules; deep detection belongs to the LLM layer).
- base64 wrap (miss): `base64-wrapped key: c2stYWJjZGVmZ2hpamtsbW5vcA==`
- string concat (miss): `key = "sk-" + "abcdef1234567890"`
- split across lines (miss): `token: sk-
  abcdef1234567890`
- zero-width space (miss): `sk-abc​def1234567890`

Verdict: PASS
