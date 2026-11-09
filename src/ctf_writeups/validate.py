"""Check that every write-up follows the one format and is indexed by known techniques."""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ctf_writeups.parse import ParseError, parse
from ctf_writeups.techniques import CATEGORIES, SLUG, Technique

REQUIRED_SECTIONS = ("Recon", "Dead ends", "Exploit", "Lesson learned")
DIFFICULTIES = ("easy", "medium", "hard")
REQUIRED_KEYS: dict[str, type] = {
    "title": str,
    "slug": str,
    "category": str,
    "platform": str,
    "event": str,
    "solved": dt.date,
    "difficulty": str,
    "techniques": list,
    "flag_sha256": str,
}
OPTIONAL_KEYS: dict[str, type] = {"summary": str}
MAX_BYTES = 256 * 1024
WRITEUPS_DIR = "writeups"
INDEX_NAME = "INDEX.md"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FLAG_LIKE = re.compile(r"[A-Za-z0-9_]{2,16}\{[^{}\s]{1,200}\}")


@dataclass(frozen=True)
class Problem:
    """One rule a write-up breaks, with the file and line."""

    path: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


@dataclass(frozen=True)
class WriteUp:
    """A write-up that passed every check."""

    path: str
    title: str
    slug: str
    category: str
    platform: str
    event: str
    solved: dt.date
    difficulty: str
    techniques: tuple[str, ...]
    flag_sha256: str
    summary: str


def _check_meta(meta: dict[str, Any], stem: str, vocab: dict[str, Technique], today: dt.date) -> list[tuple[int, str]]:
    """Front matter problems as (line offset, message); offsets are relative to line 1."""
    out: list[str] = []
    allowed = REQUIRED_KEYS | OPTIONAL_KEYS
    out += [f"unknown front matter key '{k}'" for k in sorted(set(meta) - set(allowed))]
    out += [f"missing front matter key '{k}'" for k in REQUIRED_KEYS if k not in meta]
    for key, typ in allowed.items():
        if key not in meta:
            continue
        val = meta[key]
        bad_type = not isinstance(val, typ) or (typ is dt.date and isinstance(val, dt.datetime))
        if bad_type:
            out.append(f"'{key}' must be a {'date (YYYY-MM-DD)' if typ is dt.date else typ.__name__}")
        elif typ is str and not val.strip():
            out.append(f"'{key}' must not be empty")
    if isinstance(meta.get("slug"), str):
        slug = meta["slug"]
        if not SLUG.match(slug):
            out.append("'slug' must be lower-case words joined by '-'")
        elif slug != stem:
            out.append(f"'slug' {slug!r} does not match the file name {stem!r}")
    if isinstance(meta.get("category"), str) and meta["category"] not in CATEGORIES:
        out.append(f"'category' must be one of {list(CATEGORIES)}")
    if isinstance(meta.get("difficulty"), str) and meta["difficulty"] not in DIFFICULTIES:
        out.append(f"'difficulty' must be one of {list(DIFFICULTIES)}")
    solved = meta.get("solved")
    if isinstance(solved, dt.date) and not isinstance(solved, dt.datetime) and solved > today:
        out.append(f"'solved' {solved.isoformat()} is in the future (today is {today.isoformat()} UTC)")
    techs = meta.get("techniques")
    if isinstance(techs, list):
        if not techs:
            out.append("'techniques' must list at least one technique")
        seen: set[str] = set()
        for t in techs:
            if not isinstance(t, str):
                out.append("'techniques' must contain strings")
            elif t in seen:
                out.append(f"technique '{t}' is listed twice")
            elif t not in vocab:
                out.append(f"unknown technique '{t}' (add it to techniques.toml first)")
            if isinstance(t, str):
                seen.add(t)
    sha = meta.get("flag_sha256")
    if isinstance(sha, str) and sha.strip() and not SHA256.match(sha):
        out.append("'flag_sha256' must be 64 lower-case hex characters")
    return [(1, m) for m in out]


def check_text(
    text: str, rel: str, vocab: dict[str, Technique], today: dt.date
) -> tuple[WriteUp | None, list[Problem]]:
    """Validate one write-up's text; returns the write-up only when there are no problems."""
    stem = Path(rel).stem
    try:
        doc = parse(text)
    except ParseError as exc:
        return None, [Problem(rel, exc.line, exc.message)]
    found = [Problem(rel, line, msg) for line, msg in _check_meta(doc.meta, stem, vocab, today)]
    found += [
        Problem(rel, h.line, "no '# ' headings: the title lives in the front matter")
        for h in doc.headings
        if h.level == 1
    ]
    if doc.preamble.strip():
        found.append(
            Problem(rel, doc.body_line, f"text before the first section; start with '## {REQUIRED_SECTIONS[0]}'")
        )
    titles = [s.title for s in doc.sections]
    for s in doc.sections:
        if s.title not in REQUIRED_SECTIONS:
            found.append(Problem(rel, s.line, f"unexpected section '## {s.title}'; allowed: {list(REQUIRED_SECTIONS)}"))
        elif titles.count(s.title) > 1:
            found.append(Problem(rel, s.line, f"section '## {s.title}' appears more than once"))
        elif not s.body.strip():
            found.append(Problem(rel, s.line, f"section '## {s.title}' is empty"))
    found += [Problem(rel, doc.body_line, f"missing section '## {r}'") for r in REQUIRED_SECTIONS if r not in titles]
    present = [t for t in titles if t in REQUIRED_SECTIONS]
    if len(set(present)) == len(present) and present != [r for r in REQUIRED_SECTIONS if r in present]:
        found.append(Problem(rel, doc.body_line, f"sections out of order; expected {list(REQUIRED_SECTIONS)}"))
    sha = doc.meta.get("flag_sha256")
    if isinstance(sha, str) and SHA256.match(sha):
        for hit in FLAG_LIKE.finditer(text):
            if hashlib.sha256(hit.group(0).encode()).hexdigest() == sha:
                line = text.count("\n", 0, hit.start()) + 1
                found.append(Problem(rel, line, "the real flag is written out; keep only its sha256"))
    if found:
        return None, found
    m = doc.meta
    return (
        WriteUp(
            rel,
            m["title"].strip(),
            m["slug"],
            m["category"],
            m["platform"].strip(),
            m["event"].strip(),
            m["solved"],
            m["difficulty"],
            tuple(m["techniques"]),
            m["flag_sha256"],
            m.get("summary", "").strip(),
        ),
        [],
    )


def read_text(path: Path, rel: str) -> tuple[str | None, list[Problem]]:
    """Read a write-up as UTF-8 with a size bound."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, [Problem(rel, 1, f"cannot read file: {exc.strerror}")]
    if len(raw) > MAX_BYTES:
        return None, [Problem(rel, 1, f"file is larger than {MAX_BYTES} bytes")]
    try:
        return raw.decode("utf-8"), []
    except UnicodeDecodeError as exc:
        return None, [Problem(rel, 1, f"not UTF-8 (byte {exc.start})")]


def check_tree(root: Path, vocab: dict[str, Technique], today: dt.date) -> tuple[list[WriteUp], list[Problem]]:
    """Validate every write-up under <root>/writeups and the rules that span files."""
    base = root / WRITEUPS_DIR
    if not base.is_dir():
        return [], [Problem(WRITEUPS_DIR, 0, "directory not found")]
    good: list[WriteUp] = []
    problems: list[Problem] = []
    real_base = base.resolve()
    for path in sorted(base.rglob("*.md")):
        rel = path.relative_to(root).as_posix()
        if path.parent == base and path.name == INDEX_NAME:
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(real_base):
            problems.append(Problem(rel, 0, "symbolic links are not allowed"))
            continue
        parts = path.relative_to(base).parts
        text, errs = read_text(path, rel)
        if text is None:
            problems += errs
            continue
        wu, errs = check_text(text, rel, vocab, today)
        problems += errs
        if wu is None:
            continue
        if len(parts) != 2 or parts[0] != wu.category:
            problems.append(Problem(rel, 1, f"must live in {WRITEUPS_DIR}/{wu.category}/{wu.slug}.md"))
            continue
        good.append(wu)
    seen: dict[str, str] = {}
    for wu in good:
        if wu.slug in seen:
            problems.append(Problem(wu.path, 1, f"slug '{wu.slug}' already used by {seen[wu.slug]}"))
        seen.setdefault(wu.slug, wu.path)
    if not good and not problems:
        problems.append(Problem(WRITEUPS_DIR, 0, "no write-ups found"))
    return good, problems


def today_utc() -> dt.date:
    """Today's date in UTC, so the future-date rule does not depend on the local zone."""
    return dt.datetime.now(dt.UTC).date()
