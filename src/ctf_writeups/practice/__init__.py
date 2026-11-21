"""Practice challenges shipped in this repo, each with a solver that attacks only its public interface.

The targets are deliberately weak, run in-process, and hold obviously fake flags. They exist so every
write-up in `writeups/` can be checked against a solve that really runs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class SolveResult:
    """The recovered flag and how many oracle or target calls the attack needed."""

    flag: str
    queries: int


def solvers() -> dict[str, Callable[[], SolveResult]]:
    """Every practice solver by the slug of its write-up."""
    from ctf_writeups.practice import cbc_oracle, png_meta, sqli_login, xor_note

    return {
        "sqli-login-bypass": sqli_login.solve,
        "cbc-padding-oracle": cbc_oracle.solve,
        "xor-internal-note": xor_note.solve,
        "png-hidden-chunk": png_meta.solve,
    }
