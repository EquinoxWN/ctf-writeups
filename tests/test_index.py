"""Technique index rendering and atomic writes."""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

import pytest
from conftest import SHA

from ctf_writeups.index import HEADER, render_index, write_atomic
from ctf_writeups.techniques import Technique
from ctf_writeups.validate import WriteUp


def wu(slug: str, category: str, techniques: tuple[str, ...], title: str | None = None) -> WriteUp:
    """A validated write-up for index tests."""
    return WriteUp(
        f"writeups/{category}/{slug}.md",
        title or slug,
        slug,
        category,
        "practice",
        "event",
        dt.date(2026, 11, 1),
        "easy",
        techniques,
        SHA,
        "",
    )


def test_index_groups_write_ups_by_technique_and_counts_categories(vocab: dict[str, Technique]) -> None:
    items = [wu("b", "web", ("sql-injection",)), wu("a", "crypto", ("padding-oracle", "sql-injection"))]
    text = render_index(items, vocab)
    assert text.startswith(HEADER)
    assert "2 write-ups, 2 techniques covered." in text
    assert "| web | 1 |" in text
    assert "| crypto | 1 |" in text
    assert "| pwn | 0 |" in text
    sqli = text.index("## SQL injection (CWE-89)")
    assert text.index("[a](crypto/a.md)", sqli) < text.index("[b](web/b.md)", sqli)
    assert text.index("## Padding oracle") < sqli
    assert "## Not covered yet\n\n- ROP (`rop`, pwn)" in text


def test_index_is_deterministic_whatever_the_input_order(vocab: dict[str, Technique]) -> None:
    items = [wu("b", "web", ("sql-injection",)), wu("a", "web", ("sql-injection",)), wu("c", "pwn", ("rop",))]
    assert render_index(items, vocab) == render_index(list(reversed(items)), vocab)


def test_table_cells_are_escaped(vocab: dict[str, Technique]) -> None:
    text = render_index([wu("a", "web", ("sql-injection",), title="a | b")], vocab)
    assert "[a \\| b](web/a.md)" in text


def test_no_write_ups_lists_every_technique_as_not_covered(vocab: dict[str, Technique]) -> None:
    text = render_index([], vocab)
    assert "0 write-ups, 0 techniques covered." in text
    assert text.count("\n- ") == 3


def test_atomic_write_replaces_the_file_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "INDEX.md"
    write_atomic(target, "one\n")
    write_atomic(target, "two\n")
    assert target.read_bytes() == b"two\n"
    assert os.listdir(target.parent) == ["INDEX.md"]


def test_failed_write_keeps_the_old_file_and_removes_the_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "INDEX.md"
    target.write_text("old", encoding="utf-8")

    def boom(src: str, dst: Path) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        write_atomic(target, "new")
    assert target.read_text(encoding="utf-8") == "old"
    assert os.listdir(tmp_path) == ["INDEX.md"]
