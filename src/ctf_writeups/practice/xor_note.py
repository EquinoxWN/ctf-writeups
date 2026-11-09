"""Practice crypto challenge: an internal note under a repeating-key XOR with a known header."""

from __future__ import annotations

import hashlib
from itertools import cycle

from ctf_writeups.practice import SolveResult

FLAG = "flag{EXAMPLE-NOT-A-SECRET-headers-are-cribs}"
HEADER = b"INTERNAL NOTE v1\n"
_KEY = hashlib.sha256(b"EXAMPLE-NOT-A-SECRET xor key").digest()[:12]
_NOTE = HEADER + f"to: ops\nThe staging flag is {FLAG}. Rotate it after the event.\n".encode()
MAX_KEY = 16


def xor_repeat(data: bytes, key: bytes) -> bytes:
    """XOR data with the key repeated over its length."""
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ k for b, k in zip(data, cycle(key), strict=False))


def ciphertext() -> bytes:
    """The intercepted note."""
    return xor_repeat(_NOTE, _KEY)


def _printable(data: bytes) -> bool:
    """Every byte is printable ASCII or a newline."""
    return all(32 <= b < 127 or b == 10 for b in data)


def candidates(blob: bytes, header: bytes = HEADER, max_key: int = MAX_KEY) -> list[tuple[int, bytes]]:
    """Plaintexts for each key length the known header can fully determine."""
    out = []
    for k in range(1, min(max_key, len(header), len(blob)) + 1):
        key = xor_repeat(blob[:k], header[:k])
        plain = xor_repeat(blob, key)
        if plain.startswith(header) and _printable(plain):
            out.append((k, plain))
    return out


def solve() -> SolveResult:
    """Derive the key from the header crib and keep the key length that decrypts cleanly."""
    found = candidates(ciphertext())
    tried = min(MAX_KEY, len(HEADER))
    for _, plain in found:
        text = plain.decode("ascii")
        start = text.find("flag{")
        end = text.find("}", start)
        if start >= 0 and end > start:
            return SolveResult(text[start : end + 1], tried)
    raise RuntimeError("no key length gave a readable note")
