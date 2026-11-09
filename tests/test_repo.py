"""The write-ups shipped in this repository pass every rule and match their solves."""

from __future__ import annotations

import hashlib
import re

from conftest import REPO

from ctf_writeups.index import render_index
from ctf_writeups.practice import solvers
from ctf_writeups.techniques import load_vocabulary
from ctf_writeups.validate import check_tree, today_utc


def test_every_shipped_write_up_passes_and_the_index_is_current() -> None:
    vocab = load_vocabulary(REPO / "techniques.toml")
    good, problems = check_tree(REPO, vocab, today_utc())
    assert [str(p) for p in problems] == []
    assert len(good) == 4
    index = (REPO / "writeups" / "INDEX.md").read_text(encoding="utf-8")
    assert index == render_index(good, vocab)


def test_every_practice_solver_has_a_write_up_with_its_flag_hash() -> None:
    vocab = load_vocabulary(REPO / "techniques.toml")
    good, _ = check_tree(REPO, vocab, today_utc())
    hashes = {w.slug: w.flag_sha256 for w in good}
    for slug, solve in solvers().items():
        assert hashes[slug] == hashlib.sha256(solve().flag.encode()).hexdigest(), slug


def test_no_real_looking_secrets_in_fixtures_or_write_ups() -> None:
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted((REPO / "src").rglob("*.py")))
    text += "\n".join(p.read_text(encoding="utf-8") for p in sorted((REPO / "writeups").rglob("*.md")))
    for flag in re.findall(r"flag\{[^{}\s]+\}", text):
        assert "EXAMPLE" in flag or flag in {"flag{...}"}, flag
    assert not re.search(r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[0-9A-Za-z]{36})", text)
