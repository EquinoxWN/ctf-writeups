+++
title = "Session token through a CBC padding oracle"
slug = "cbc-padding-oracle"
category = "crypto"
platform = "ctf-writeups practice set"
event = "Practice set, challenge 2"
solved = 2026-11-08
difficulty = "medium"
techniques = ["padding-oracle"]
flag_sha256 = "de7409ab7e6fb1233b66aa51252738a818f6599528a7fedd41d969c89bbe1ad0"
summary = "A service that reveals whether CBC padding is valid decrypts any token one byte at a time."
+++

## Recon

The target, `OracleChallenge` in
[`src/ctf_writeups/practice/cbc_oracle.py`](../../src/ctf_writeups/practice/cbc_oracle.py), hands
out an encrypted session token and accepts tokens back. The token is 96 bytes: a multiple of 16,
so a 16-byte block cipher in a chained mode with a 16-byte IV in front is the first guess.

Sending the token back is accepted. Flipping a bit in the last byte of the second-to-last block
makes the service answer differently than flipping a bit in the first block: the answer depends
on the end of the plaintext, which is where PKCS#7 padding lives. The service tells valid padding
from invalid padding, one bit per request.

## Dead ends

- **Looking for the key.** The block cipher is keyed with a 32-byte secret; nothing in the
  service leaks it, and the attack below never needs it.
- **Bit-flipping the plaintext blind.** Changing the IV changes the first plaintext block
  predictably, but without knowing the plaintext there is nothing useful to flip it into.
- **Trusting the first "valid" answer for the last byte.** A forged block can produce `\x02\x02`
  by accident instead of `\x01`. The solver re-checks that byte with the byte before it changed
  and only then accepts the guess.

## Exploit

In CBC, `P[i] = D(C[i]) xor C[i-1]`. The attacker controls `C[i-1]`. For each target block:

1. Send a forged previous block `X` followed by `C[i]`, trying all 256 values of the last byte of
   `X` until the padding is valid. Then `D(C[i])[15] xor X[15] = 0x01`, which gives the last
   intermediate byte.
2. Set the known tail to produce `0x02 0x02`, `0x03 0x03 0x03` and so on, and repeat for each
   byte to the left.
3. XOR the recovered intermediate block with the real `C[i-1]` to get the plaintext.

The whole token (5 blocks) comes back in 9,909 oracle queries, about 124 per byte against a
worst case of 256. The plaintext is `session=guest; note=the admin token is flag{...}`.

```bash
ctfw solve cbc-padding-oracle
```

The block cipher in this practice target is a small Feistel network instead of AES, so the
repository needs no crypto library. The attack does not depend on the cipher: it only uses the
padding answer.

## Lesson learned

- Any observable difference between "bad padding" and "bad data" (error text, status code,
  timing) turns CBC into a decryption oracle.
- Authenticate before decrypting: encrypt-then-MAC or an AEAD mode (AES-GCM, ChaCha20-Poly1305)
  rejects forged tokens before the padding is ever looked at.
- Edge cases matter in the exploit too: the false positive on the last byte is the one bug that
  makes naive scripts fail intermittently.
