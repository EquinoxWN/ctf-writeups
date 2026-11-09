"""Split a write-up into TOML front matter and its level-2 Markdown sections."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from typing import Any

FENCE = "+++"
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$")
_CODE_FENCE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")


class ParseError(ValueError):
    """A write-up whose structure cannot be read at all."""

    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line
        self.message = message


@dataclass(frozen=True)
class Heading:
    """A Markdown heading outside code blocks."""

    level: int
    title: str
    line: int


@dataclass(frozen=True)
class Section:
    """A level-2 heading and the text up to the next one."""

    title: str
    line: int
    body: str


@dataclass(frozen=True)
class Document:
    """Front matter, the line where the body starts, headings, sections and preamble."""

    meta: dict[str, Any]
    body_line: int
    headings: tuple[Heading, ...]
    sections: tuple[Section, ...]
    preamble: str


def split_front_matter(text: str) -> tuple[dict[str, Any], int, str]:
    """Return (front matter, first body line number, body); CRLF is read as LF."""
    lines = text.replace("\r\n", "\n").split("\n")
    if lines[0] != FENCE:
        raise ParseError(1, "a write-up must start with a '+++' front matter line")
    for i in range(1, len(lines)):
        if lines[i] == FENCE:
            try:
                meta = tomllib.loads("\n".join(lines[1:i]))
            except tomllib.TOMLDecodeError as exc:
                raise ParseError(2, f"front matter is not valid TOML: {exc}") from exc
            return meta, i + 2, "\n".join(lines[i + 1 :])
    raise ParseError(1, "front matter is not closed with a '+++' line")


def headings(body: str, first_line: int) -> tuple[Heading, ...]:
    """Headings in the body, skipping fenced code blocks."""
    found: list[Heading] = []
    fence: str | None = None
    for offset, raw in enumerate(body.split("\n")):
        line = raw.rstrip("\r")
        marker = _CODE_FENCE.match(line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token[0] * len(token)
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        m = _HEADING.match(line)
        if m:
            found.append(Heading(len(m.group(1)), m.group(2), first_line + offset))
    return tuple(found)


def parse(text: str) -> Document:
    """Parse a whole write-up into a Document."""
    meta, body_line, body = split_front_matter(text)
    heads = headings(body, body_line)
    lines = body.split("\n")
    level2 = [h for h in heads if h.level == 2]
    sections: list[Section] = []
    for i, h in enumerate(level2):
        start = h.line - body_line + 1
        end = level2[i + 1].line - body_line if i + 1 < len(level2) else len(lines)
        sections.append(Section(h.title, h.line, "\n".join(lines[start:end])))
    first = level2[0].line - body_line if level2 else len(lines)
    return Document(meta, body_line, heads, tuple(sections), "\n".join(lines[:first]))
