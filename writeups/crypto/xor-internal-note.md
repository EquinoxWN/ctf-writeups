+++
title = "Internal note under a repeating XOR key"
slug = "xor-internal-note"
category = "crypto"
platform = "ctf-writeups practice set"
event = "Practice set, challenge 3"
solved = 2026-11-08
difficulty = "easy"
techniques = ["repeating-key-xor", "known-plaintext"]
flag_sha256 = "153f54960340e1de90b12e00ffa3b96f8d76d0faf21af01f1669c1eb2337d2e9"
summary = "A fixed note header is a crib long enough to recover a 12-byte XOR key."
+++

## Recon

The challenge in [`src/ctf_writeups/practice/xor_note.py`](../../src/ctf_writeups/practice/xor_note.py)
gives an intercepted blob of 118 bytes and says it is an internal note. Every internal note
in the challenge description starts with the same header, `INTERNAL NOTE v1` and a newline
(17 bytes). The bytes look random, but the description says the tool "XORs with a short key",
so a repeating key is the working assumption.

## Dead ends

- **Single-byte XOR.** Trying all 256 single-byte keys gives no printable plaintext; the key is
  longer than one byte.
- **Frequency analysis per key position.** With 118 bytes and an unknown key length, each
  column has about 10 bytes, too few for letter frequencies to be reliable.

## Exploit

A known plaintext at a known position gives the key directly: `key[i] = C[i] xor P[i]`. The
header is 17 bytes, so any key of up to 17 bytes is fully determined by it. The solver:

1. For each key length `k` from 1 to 16, takes `key = C[:k] xor header[:k]`.
2. Decrypts the whole blob with that key repeated.
3. Keeps the length whose plaintext starts with the full header and is printable ASCII.

Only `k = 12` passes; shorter keys reproduce the first `k` header bytes and then fall apart. The
note reads `The staging flag is flag{...}. Rotate it after the event.`

```bash
ctfw solve xor-internal-note
```

## Lesson learned

- Fixed headers, file magic numbers and flag prefixes are cribs. A repeating key shorter than the
  crib is broken outright.
- Checking the candidate against the rest of the crib (not just the bytes used to derive it)
  selects the right key length without any statistics.
- XOR with a reused key is not encryption; use an AEAD cipher with a fresh nonce per message.
