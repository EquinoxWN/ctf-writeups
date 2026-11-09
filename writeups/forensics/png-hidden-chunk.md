+++
title = "Flag in a compressed PNG text chunk"
slug = "png-hidden-chunk"
category = "forensics"
platform = "ctf-writeups practice set"
event = "Practice set, challenge 4"
solved = 2026-11-08
difficulty = "easy"
techniques = ["file-format-metadata", "decoy-filtering"]
flag_sha256 = "0f6f8e2ef31cafab866e3aa62b00cbcbcaed4a394f12664cfb90c746fc4e2f16"
summary = "strings finds a decoy; walking the PNG chunks finds the real flag in a zTXt chunk."
+++

## Recon

The file from [`src/ctf_writeups/practice/png_meta.py`](../../src/ctf_writeups/practice/png_meta.py)
(`build_image()`) is a valid 1x1 PNG. The image itself is a single green pixel, so the flag is
not in the picture. PNG stores metadata in named chunks (`tEXt`, `zTXt`, `iTXt`), each with a
length, a type, data and a CRC, which makes the file easy to walk.

## Dead ends

- **`strings` on the file.** It shows one flag-shaped string in a `Comment` text chunk. The
  scoreboard rejects it: it is a decoy, placed where a quick look would find it.
- **Looking at the pixels.** One pixel, no room for steganography.

## Exploit

Walk the chunks instead of grepping the bytes:

1. Check the 8-byte PNG signature.
2. Read each chunk's length and type, check the length stays inside the file and the CRC
   matches, and stop at `IEND`.
3. For `tEXt`, split keyword and text at the first zero byte. For `zTXt`, the text after the
   keyword and the compression byte is zlib data: inflate it, with an output cap so a crafted
   chunk cannot exhaust memory.

The `zTXt` chunk with keyword `Secret` holds the real flag. `strings` missed it because it is
compressed. The solver submits every flag-shaped string it finds, in file order, and the second
submission is accepted.

```bash
ctfw solve png-hidden-chunk
```

## Lesson learned

- `strings` only sees uncompressed text. Parse the container format and decompress what it
  compresses.
- Expect decoys: a candidate is not a flag until the scoreboard accepts it, so collect all
  candidates instead of stopping at the first.
- Parsers for untrusted files need bounds: chunk lengths checked against the file size, CRCs
  verified, a chunk count limit and a cap on decompressed size.
