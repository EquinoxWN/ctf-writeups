"""Practice forensics challenge: a flag in a compressed PNG text chunk behind a decoy."""

from __future__ import annotations

import re
import struct
import zlib

from ctf_writeups.practice import SolveResult

FLAG = "flag{EXAMPLE-NOT-A-SECRET-read-every-chunk}"
DECOY = "flag{EXAMPLE-decoy-strings-is-not-enough}"
SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_TEXT = 64 * 1024
MAX_CHUNKS = 1024
_FLAG_RE = re.compile(r"flag\{[^{}\s]{1,200}\}")


class PngError(ValueError):
    """The file is not a well-formed PNG."""


def _chunk(kind: bytes, data: bytes) -> bytes:
    """Length, type, data and CRC of one chunk."""
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def build_image() -> bytes:
    """A 1x1 PNG with a visible decoy comment and the flag in a zTXt chunk."""
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    return (
        SIGNATURE
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"tEXt", b"Comment\x00" + DECOY.encode())
        + _chunk(b"zTXt", b"Secret\x00\x00" + zlib.compress(FLAG.encode()))
        + _chunk(b"IDAT", pixels)
        + _chunk(b"IEND", b"")
    )


def chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    """Split a PNG into (type, data) pairs, checking bounds and CRCs."""
    if not data.startswith(SIGNATURE):
        raise PngError("missing PNG signature")
    out: list[tuple[bytes, bytes]] = []
    pos = len(SIGNATURE)
    while pos < len(data):
        if len(out) >= MAX_CHUNKS:
            raise PngError("too many chunks")
        if pos + 8 > len(data):
            raise PngError("truncated chunk header")
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        kind = data[pos + 4 : pos + 8]
        end = pos + 8 + length
        if end + 4 > len(data):
            raise PngError(f"chunk {kind!r} runs past the end of the file")
        body = data[pos + 8 : end]
        (crc,) = struct.unpack(">I", data[end : end + 4])
        if zlib.crc32(kind + body) != crc:
            raise PngError(f"bad CRC in chunk {kind!r}")
        out.append((kind, body))
        pos = end + 4
        if kind == b"IEND":
            break
    if not out or out[-1][0] != b"IEND":
        raise PngError("no IEND chunk")
    return out


def _inflate(blob: bytes) -> bytes:
    """Decompress with an output cap so a zip bomb cannot exhaust memory."""
    d = zlib.decompressobj()
    try:
        out = d.decompress(blob, MAX_TEXT)
    except zlib.error as exc:
        raise PngError(f"bad compressed text: {exc}") from exc
    if d.unconsumed_tail:
        raise PngError(f"compressed text is larger than {MAX_TEXT} bytes")
    return out


def texts(data: bytes) -> list[tuple[str, str]]:
    """Every (keyword, text) pair from tEXt and zTXt chunks."""
    out = []
    for kind, body in chunks(data):
        if kind not in (b"tEXt", b"zTXt"):
            continue
        keyword, sep, rest = body.partition(b"\x00")
        if not sep:
            raise PngError(f"{kind!r} chunk without a keyword separator")
        if kind == b"zTXt":
            if not rest or rest[0] != 0:
                raise PngError("unknown zTXt compression method")
            rest = _inflate(rest[1:])
        out.append((keyword.decode("latin-1"), rest.decode("latin-1")))
    return out


class Scoreboard:
    """Accepts flag submissions and counts them."""

    def __init__(self) -> None:
        self.submissions = 0

    def submit(self, candidate: str) -> bool:
        """True when the candidate is the flag."""
        self.submissions += 1
        return candidate == FLAG


def solve() -> SolveResult:
    """Read every text chunk, including compressed ones, and submit each flag-shaped string."""
    board = Scoreboard()
    for _, text in texts(build_image()):
        for cand in _FLAG_RE.findall(text):
            if board.submit(cand):
                return SolveResult(cand, board.submissions)
    raise RuntimeError("no accepted flag in any text chunk")
