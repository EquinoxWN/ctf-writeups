"""Front matter splitting and section extraction."""

from __future__ import annotations

import datetime as dt

import pytest
from conftest import VALID

from ctf_writeups.parse import ParseError, headings, parse, split_front_matter


def test_front_matter_is_parsed_as_toml_with_native_dates() -> None:
    meta, body_line, body = split_front_matter(VALID)
    assert meta["solved"] == dt.date(2026, 11, 1)
    assert meta["techniques"] == ["sql-injection"]
    assert body_line == 12
    assert body.startswith("\n## Recon")


def test_crlf_line_endings_are_accepted() -> None:
    doc = parse(VALID.replace("\n", "\r\n"))
    assert [s.title for s in doc.sections] == ["Recon", "Dead ends", "Exploit", "Lesson learned"]


@pytest.mark.parametrize(
    ("text", "line", "fragment"),
    [
        ("", 1, "must start"),
        ("title = 'x'\n", 1, "must start"),
        ("﻿+++\n+++\n", 1, "must start"),
        ("+++\ntitle = 'x'\n", 1, "not closed"),
        ("+++\ntitle = \n+++\n", 2, "not valid TOML"),
    ],
)
def test_broken_front_matter_raises_with_a_line(text: str, line: int, fragment: str) -> None:
    with pytest.raises(ParseError) as exc:
        split_front_matter(text)
    assert exc.value.line == line
    assert fragment in exc.value.message


def test_headings_inside_fenced_code_are_ignored() -> None:
    body = "## A\n```\n## not\n~~~\n## still code\n```\n## B\n~~~~\n```\n## code\n~~~~\n## C"
    assert [h.title for h in headings(body, 1)] == ["A", "B", "C"]


def test_heading_lines_are_counted_from_the_body_start() -> None:
    hs = headings("\n## A\ntext\n### Sub ###\n", 20)
    assert [(h.level, h.title, h.line) for h in hs] == [(2, "A", 21), (3, "Sub", 23)]


def test_hash_without_space_is_not_a_heading() -> None:
    assert headings("#hashtag\n##no", 1) == ()


def test_section_bodies_keep_subsections_and_code() -> None:
    doc = parse(VALID)
    exploit = doc.sections[2]
    assert exploit.title == "Exploit"
    assert "### Payload" in exploit.body
    assert "## not a heading inside code" in exploit.body
    assert doc.sections[3].body.strip() == "Use bound parameters."
    assert doc.preamble.strip() == ""


def test_text_before_the_first_section_is_the_preamble() -> None:
    doc = parse("+++\n+++\nintro\n## Recon\nx\n")
    assert doc.preamble.strip() == "intro"
    assert doc.sections[0].line == 4


def test_body_without_sections_is_all_preamble() -> None:
    doc = parse("+++\n+++\njust text\n")
    assert doc.sections == ()
    assert "just text" in doc.preamble
