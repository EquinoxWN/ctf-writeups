"""Practice crypto challenge: a CBC padding oracle on a toy 128-bit block cipher.

The cipher is a 4-round Feistel network with HMAC-SHA256 round functions. It is a teaching
stand-in for AES (the attack never looks inside the cipher) and must not be used to protect data.
"""

from __future__ import annotations

import hashlib
import hmac

from ctf_writeups.practice import SolveResult

BLOCK = 16
ROUNDS = 4
FLAG = "flag{EXAMPLE-NOT-A-SECRET-padding-talks}"
_KEY = hashlib.sha256(b"EXAMPLE-NOT-A-SECRET cbc key").digest()
_IV = hashlib.sha256(b"EXAMPLE-NOT-A-SECRET cbc iv").digest()[:BLOCK]
MESSAGE = f"session=guest; note=the admin token is {FLAG}".encode()


class PaddingError(ValueError):
    """The decrypted plaintext does not end in valid PKCS#7 padding."""


def _xor(a: bytes, b: bytes) -> bytes:
    """Byte-wise XOR of equal-length strings."""
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


class ToyBlockCipher:
    """A 16-byte Feistel block cipher keyed by HMAC-SHA256."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 16:
            raise ValueError("key must be at least 16 bytes")
        self._key = key

    def _f(self, rnd: int, half: bytes) -> bytes:
        """Round function."""
        return hmac.new(self._key, bytes([rnd]) + half, hashlib.sha256).digest()[: BLOCK // 2]

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one block."""
        if len(block) != BLOCK:
            raise ValueError("block must be 16 bytes")
        left, right = block[: BLOCK // 2], block[BLOCK // 2 :]
        for rnd in range(ROUNDS):
            left, right = right, _xor(left, self._f(rnd, right))
        return left + right

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt one block."""
        if len(block) != BLOCK:
            raise ValueError("block must be 16 bytes")
        left, right = block[: BLOCK // 2], block[BLOCK // 2 :]
        for rnd in reversed(range(ROUNDS)):
            left, right = _xor(right, self._f(rnd, left)), left
        return left + right


def pad(data: bytes) -> bytes:
    """PKCS#7 padding to a whole number of blocks."""
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    """Strip PKCS#7 padding or raise PaddingError."""
    if not data or len(data) % BLOCK:
        raise PaddingError("length is not a whole number of blocks")
    n = data[-1]
    if not 1 <= n <= BLOCK or data[-n:] != bytes([n]) * n:
        raise PaddingError("bad padding")
    return data[:-n]


def cbc_encrypt(cipher: ToyBlockCipher, iv: bytes, plain: bytes) -> bytes:
    """CBC-encrypt; the IV is prepended to the output."""
    out, prev = [iv], iv
    data = pad(plain)
    for i in range(0, len(data), BLOCK):
        prev = cipher.encrypt_block(_xor(data[i : i + BLOCK], prev))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(cipher: ToyBlockCipher, data: bytes) -> bytes:
    """CBC-decrypt IV-prefixed data and strip padding."""
    if len(data) < 2 * BLOCK or len(data) % BLOCK:
        raise PaddingError("length is not IV plus whole blocks")
    out = [_xor(cipher.decrypt_block(data[i : i + BLOCK]), data[i - BLOCK : i]) for i in range(BLOCK, len(data), BLOCK)]
    return unpad(b"".join(out))


class OracleChallenge:
    """A service that leaks one bit per request: was the padding valid."""

    def __init__(self, key: bytes = _KEY, iv: bytes = _IV, message: bytes = MESSAGE) -> None:
        self._cipher = ToyBlockCipher(key)
        self._token = cbc_encrypt(self._cipher, iv, message)
        self.queries = 0

    def token(self) -> bytes:
        """The intercepted IV-prefixed ciphertext."""
        return self._token

    def oracle(self, data: bytes) -> bool:
        """True when the token decrypts to valid padding (the leak)."""
        self.queries += 1
        try:
            cbc_decrypt(self._cipher, data)
        except PaddingError:
            return False
        return True


def _recover_block(oracle: OracleChallenge, prev: bytes, cur: bytes) -> bytes:
    """Decrypt one block from padding answers alone."""
    inter = bytearray(BLOCK)
    for pos in range(BLOCK - 1, -1, -1):
        n = BLOCK - pos
        forged = bytearray(BLOCK)
        for j in range(pos + 1, BLOCK):
            forged[j] = inter[j] ^ n
        for guess in range(256):
            forged[pos] = guess
            if not oracle.oracle(bytes(forged) + cur):
                continue
            if pos == BLOCK - 1:
                forged[pos - 1] ^= 0xFF
                ok = oracle.oracle(bytes(forged) + cur)
                forged[pos - 1] ^= 0xFF
                if not ok:
                    continue
            inter[pos] = guess ^ n
            break
        else:
            raise RuntimeError(f"no padding byte found at position {pos}")
    return _xor(bytes(inter), prev)


def decrypt_with_oracle(oracle: OracleChallenge, token: bytes) -> bytes:
    """Recover the whole plaintext of an IV-prefixed token."""
    if len(token) < 2 * BLOCK or len(token) % BLOCK:
        raise ValueError("token must be IV plus whole blocks")
    blocks = [token[i : i + BLOCK] for i in range(0, len(token), BLOCK)]
    plain = b"".join(_recover_block(oracle, blocks[i - 1], blocks[i]) for i in range(1, len(blocks)))
    return unpad(plain)


def solve() -> SolveResult:
    """Run the padding oracle attack and pull the flag out of the plaintext."""
    target = OracleChallenge()
    plain = decrypt_with_oracle(target, target.token()).decode("ascii")
    start = plain.find("flag{")
    end = plain.find("}", start)
    if start < 0 or end < 0:
        raise RuntimeError("no flag in the recovered plaintext")
    return SolveResult(plain[start : end + 1], target.queries)
