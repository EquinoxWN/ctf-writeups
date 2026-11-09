"""The controlled technique vocabulary every write-up is indexed by."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

CATEGORIES = ("web", "pwn", "crypto", "forensics", "reversing", "misc")
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CWE = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
_KEYS = {"name", "category", "cwe"}
MAX_VOCAB_BYTES = 64 * 1024


class VocabularyError(ValueError):
    """The technique file is missing or malformed; lists every problem."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class Technique:
    """One technique: id, display name, home category and optional CWE."""

    id: str
    name: str
    category: str
    cwe: str | None


def parse_vocabulary(text: str) -> dict[str, Technique]:
    """Validate TOML tables of techniques and return them by id."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise VocabularyError([f"not valid TOML: {exc}"]) from exc
    problems: list[str] = []
    out: dict[str, Technique] = {}
    if not data:
        problems.append("no techniques defined")
    for tid, entry in data.items():
        if not SLUG.match(tid):
            problems.append(f"{tid!r}: id must be lower-case words joined by '-'")
            continue
        if not isinstance(entry, dict):
            problems.append(f"{tid}: must be a table")
            continue
        unknown = sorted(set(entry) - _KEYS)
        if unknown:
            problems.append(f"{tid}: unknown keys {unknown}")
        name, category, cwe = entry.get("name"), entry.get("category"), entry.get("cwe")
        if not isinstance(name, str) or not name.strip():
            problems.append(f"{tid}: 'name' must be a non-empty string")
        if category not in CATEGORIES:
            problems.append(f"{tid}: 'category' must be one of {list(CATEGORIES)}")
        if cwe is not None and (not isinstance(cwe, str) or not CWE.match(cwe)):
            problems.append(f"{tid}: 'cwe' must look like CWE-89")
        if isinstance(name, str) and name.strip() and category in CATEGORIES:
            out[tid] = Technique(tid, name.strip(), str(category), cwe)
    if problems:
        raise VocabularyError(problems)
    return out


def load_vocabulary(path: Path) -> dict[str, Technique]:
    """Read and validate the technique file."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VocabularyError([f"cannot read {path.name}: {exc.strerror}"]) from exc
    if len(raw) > MAX_VOCAB_BYTES:
        raise VocabularyError([f"{path.name} is larger than {MAX_VOCAB_BYTES} bytes"])
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VocabularyError([f"{path.name} is not UTF-8"]) from exc
    return parse_vocabulary(text)
