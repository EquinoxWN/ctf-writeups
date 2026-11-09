"""Practice targets behave as their write-ups describe, and each solver recovers the flag."""

from __future__ import annotations

import random
import re
import struct
import zlib

import pytest

from ctf_writeups.practice import cbc_oracle, png_meta, solvers, sqli_login, xor_note

FAKE = re.compile(r"^flag\{EXAMPLE-NOT-A-SECRET-[a-z-]+\}$")


@pytest.mark.parametrize("slug", sorted(solvers()))
def test_each_solver_recovers_an_obviously_fake_flag(slug: str) -> None:
    result = solvers()[slug]()
    assert FAKE.match(result.flag), result.flag
    assert result.queries > 0


# SQL injection


def test_sqli_payload_logs_in_as_admin_and_the_fix_blocks_it() -> None:
    with sqli_login.LoginChallenge() as t:
        assert t.login("admin", "admin") == "invalid credentials"
        assert t.login("admin'", "x") == "database error"
        assert t.login("guest", "guest") == "welcome guest"
        assert t.login("x", "' OR '1'='1") == "welcome guest"
        assert sqli_login.FLAG in t.login("admin'--", "x")
        assert t.login_fixed("admin'--", "x") == "invalid credentials"
        assert t.login_fixed("x", "' OR '1'='1") == "invalid credentials"
        assert t.login_fixed("guest", "guest") == "welcome guest"


def test_sqli_solver_needs_three_attempts() -> None:
    assert sqli_login.solve().queries == 3


def test_extract_flag_handles_pages_without_a_flag() -> None:
    assert sqli_login.extract_flag("welcome guest") is None
    assert sqli_login.extract_flag("flag{open") is None
    assert sqli_login.extract_flag("x flag{a} y") == "flag{a}"


# CBC padding oracle


def test_toy_cipher_round_trips_random_blocks_and_keys() -> None:
    rng = random.Random(7)
    for _ in range(200):
        key = rng.randbytes(32)
        block = rng.randbytes(16)
        c = cbc_oracle.ToyBlockCipher(key)
        enc = c.encrypt_block(block)
        assert enc != block
        assert c.decrypt_block(enc) == block


def test_toy_cipher_rejects_short_keys_and_wrong_block_sizes() -> None:
    with pytest.raises(ValueError, match="key"):
        cbc_oracle.ToyBlockCipher(b"short")
    c = cbc_oracle.ToyBlockCipher(b"k" * 16)
    with pytest.raises(ValueError, match="16 bytes"):
        c.encrypt_block(b"x" * 15)
    with pytest.raises(ValueError, match="16 bytes"):
        c.decrypt_block(b"x" * 17)


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32])
def test_pkcs7_pad_unpad_round_trip(n: int) -> None:
    data = bytes(range(n))
    padded = cbc_oracle.pad(data)
    assert len(padded) % 16 == 0
    assert len(padded) > n
    assert cbc_oracle.unpad(padded) == data


@pytest.mark.parametrize("bad", [b"", b"x" * 15, b"x" * 15 + b"\x00", b"x" * 15 + b"\x11", b"x" * 14 + b"\x01\x02"])
def test_unpad_rejects_invalid_padding(bad: bytes) -> None:
    with pytest.raises(cbc_oracle.PaddingError):
        cbc_oracle.unpad(bad)


def test_cbc_round_trip_and_the_oracle_leak() -> None:
    t = cbc_oracle.OracleChallenge()
    token = t.token()
    assert len(token) == 96
    assert t.oracle(token)
    first = bytearray(token)
    first[0] ^= 1
    assert t.oracle(bytes(first))
    last = bytearray(token)
    last[-17] ^= 1
    assert not t.oracle(bytes(last))
    assert not t.oracle(token[:-1])
    assert not t.oracle(token[:16])
    assert t.queries == 5


def test_padding_oracle_decrypts_random_messages_within_the_query_bound() -> None:
    rng = random.Random(11)
    for size in (0, 1, 15, 16, 40):
        msg = rng.randbytes(size)
        t = cbc_oracle.OracleChallenge(key=rng.randbytes(32), iv=rng.randbytes(16), message=msg)
        assert cbc_oracle.decrypt_with_oracle(t, t.token()) == msg
        blocks = len(t.token()) // 16 - 1
        assert t.queries <= blocks * 16 * 256 + blocks


def test_padding_oracle_rejects_malformed_tokens() -> None:
    t = cbc_oracle.OracleChallenge()
    with pytest.raises(ValueError, match="whole blocks"):
        cbc_oracle.decrypt_with_oracle(t, b"x" * 20)


def test_padding_oracle_fails_loudly_when_the_oracle_never_says_yes() -> None:
    class Silent(cbc_oracle.OracleChallenge):
        def oracle(self, data: bytes) -> bool:
            return False

    t = Silent()
    with pytest.raises(RuntimeError, match="no padding byte"):
        cbc_oracle.decrypt_with_oracle(t, t.token())


def test_last_byte_false_positive_is_rejected() -> None:
    # The attack forges from a zero block, so an intermediate byte 14 equal to 0x02 makes 0x02 0x02 a
    # second valid padding; the plaintext byte 0x02 xor IV[14] produces exactly that.
    rng = random.Random(3)
    for _ in range(20):
        iv = rng.randbytes(16)
        msg = b"A" * 14 + bytes([0x02 ^ iv[14]]) + b"B"
        t = cbc_oracle.OracleChallenge(key=rng.randbytes(32), iv=iv, message=msg)
        assert cbc_oracle.decrypt_with_oracle(t, t.token()) == msg


# Repeating-key XOR


def test_xor_is_its_own_inverse_and_rejects_an_empty_key() -> None:
    assert xor_note.xor_repeat(xor_note.xor_repeat(b"hello world", b"key"), b"key") == b"hello world"
    with pytest.raises(ValueError, match="empty"):
        xor_note.xor_repeat(b"x", b"")


def test_only_the_true_key_length_survives_the_header_check() -> None:
    blob = xor_note.ciphertext()
    assert len(blob) == 118
    assert [k for k, _ in xor_note.candidates(blob)] == [12]


def test_single_byte_xor_never_gives_printable_text() -> None:
    blob = xor_note.ciphertext()
    assert not any(all(32 <= (b ^ k) < 127 or (b ^ k) == 10 for b in blob) for k in range(256))


def test_a_wrong_header_gives_no_candidates() -> None:
    assert xor_note.candidates(xor_note.ciphertext(), header=b"PUBLIC NOTE v1\n") == []


# PNG chunks


def test_png_text_chunks_include_the_decoy_and_the_compressed_flag() -> None:
    texts = png_meta.texts(png_meta.build_image())
    assert texts == [("Comment", png_meta.DECOY), ("Secret", png_meta.FLAG)]


def test_strings_on_the_raw_file_sees_only_the_decoy() -> None:
    raw = png_meta.build_image().decode("latin-1")
    assert re.findall(r"flag\{[^{}\s]+\}", raw) == [png_meta.DECOY]


def test_png_solver_needs_two_submissions() -> None:
    assert png_meta.solve().queries == 2


def _chunk(kind: bytes, data: bytes) -> bytes:
    """A correctly framed chunk for crafted inputs."""
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        (b"GIF89a", "signature"),
        (png_meta.SIGNATURE + b"\x00\x00", "truncated chunk header"),
        (png_meta.SIGNATURE + struct.pack(">I", 999) + b"tEXt" + b"x", "runs past the end"),
        (png_meta.SIGNATURE + _chunk(b"IHDR", b"x")[:-1] + b"\x00", "bad CRC"),
        (png_meta.SIGNATURE + _chunk(b"IHDR", b"x"), "no IEND"),
        (png_meta.SIGNATURE + _chunk(b"tEXt", b"nokeyword") + _chunk(b"IEND", b""), "keyword separator"),
        (png_meta.SIGNATURE + _chunk(b"zTXt", b"k\x00\x01abc") + _chunk(b"IEND", b""), "compression method"),
        (png_meta.SIGNATURE + _chunk(b"zTXt", b"k\x00\x00notzlib") + _chunk(b"IEND", b""), "bad compressed text"),
        (
            png_meta.SIGNATURE
            + _chunk(b"zTXt", b"k\x00\x00" + zlib.compress(b"\x00" * (png_meta.MAX_TEXT + 1)))
            + _chunk(b"IEND", b""),
            "larger than",
        ),
        (png_meta.SIGNATURE + _chunk(b"tEXt", b"k\x00v") * (png_meta.MAX_CHUNKS + 1), "too many chunks"),
    ],
)
def test_malformed_pngs_are_rejected(data: bytes, fragment: str) -> None:
    with pytest.raises(png_meta.PngError, match=fragment):
        png_meta.texts(data)


def test_a_tampered_byte_in_the_flag_chunk_is_detected() -> None:
    data = bytearray(png_meta.build_image())
    pos = data.index(b"zTXt") + 12
    data[pos] ^= 1
    with pytest.raises(png_meta.PngError, match="bad CRC"):
        png_meta.chunks(bytes(data))
