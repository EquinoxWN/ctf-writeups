"""ctfw: check write-ups, build the technique index, scaffold a write-up and run practice solves."""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from ctf_writeups.index import render_index, write_atomic
from ctf_writeups.practice import solvers
from ctf_writeups.techniques import CATEGORIES, SLUG, Technique, VocabularyError, load_vocabulary
from ctf_writeups.validate import INDEX_NAME, REQUIRED_SECTIONS, WRITEUPS_DIR, WriteUp, check_tree, today_utc

VOCAB_NAME = "techniques.toml"


def _load(root: Path) -> tuple[dict[str, Technique], list[WriteUp]] | None:
    """Vocabulary and valid write-ups, or None after printing every problem."""
    try:
        vocab = load_vocabulary(root / VOCAB_NAME)
    except VocabularyError as exc:
        for msg in exc.problems:
            print(f"{VOCAB_NAME}: {msg}", file=sys.stderr)
        return None
    good, problems = check_tree(root, vocab, today_utc())
    for p in problems:
        print(p, file=sys.stderr)
    return None if problems else (vocab, good)


def cmd_check(root: Path) -> int:
    """Validate every write-up."""
    loaded = _load(root)
    if loaded is None:
        print("CHECK FAILED", file=sys.stderr)
        return 1
    vocab, good = loaded
    used = {t for wu in good for t in wu.techniques}
    print(f"{len(good)} write-ups OK, {len(used)} of {len(vocab)} techniques covered, 0 problems")
    return 0


def cmd_index(root: Path, check: bool) -> int:
    """Write the index, or with --check fail when it is out of date."""
    loaded = _load(root)
    if loaded is None:
        return 1
    vocab, good = loaded
    text = render_index(good, vocab)
    path = root / WRITEUPS_DIR / INDEX_NAME
    if check:
        try:
            current = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            current = None
        if current != text:
            print(f"{WRITEUPS_DIR}/{INDEX_NAME} is out of date: run `ctfw index`", file=sys.stderr)
            return 1
        print(f"{WRITEUPS_DIR}/{INDEX_NAME} is up to date")
        return 0
    write_atomic(path, text)
    print(f"wrote {WRITEUPS_DIR}/{INDEX_NAME} ({len(good)} write-ups)")
    return 0


def template(slug: str, category: str, techniques: Sequence[str], solved: str) -> str:
    """A new write-up with the front matter and empty sections to fill in."""
    techs = ", ".join(f'"{t}"' for t in techniques)
    head = [
        "+++",
        f'title = "{slug.replace("-", " ").capitalize()}"',
        f'slug = "{slug}"',
        f'category = "{category}"',
        'platform = ""',
        'event = ""',
        f"solved = {solved}",
        'difficulty = "easy"',
        f"techniques = [{techs}]",
        'flag_sha256 = ""',
        "+++",
        "",
    ]
    body = [line for s in REQUIRED_SECTIONS for line in (f"## {s}", "", "")]
    return "\n".join(head + body)


def cmd_new(root: Path, slug: str, category: str, techniques: Sequence[str]) -> int:
    """Create a write-up skeleton; never overwrite an existing file."""
    try:
        vocab = load_vocabulary(root / VOCAB_NAME)
    except VocabularyError as exc:
        print(f"{VOCAB_NAME}: {exc}", file=sys.stderr)
        return 1
    unknown = [t for t in techniques if t not in vocab]
    if not SLUG.match(slug) or unknown:
        print(f"invalid slug {slug!r}" if not SLUG.match(slug) else f"unknown techniques: {unknown}", file=sys.stderr)
        return 1
    path = root / WRITEUPS_DIR / category / f"{slug}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as fh:
            fh.write(template(slug, category, techniques, today_utc().isoformat()))
    except FileExistsError:
        print(f"{path.relative_to(root).as_posix()} already exists", file=sys.stderr)
        return 1
    print(f"created {path.relative_to(root).as_posix()}: fill in every section, then run `ctfw check`")
    return 0


def cmd_solve(root: Path, slugs: Sequence[str]) -> int:
    """Run practice solvers and compare each flag with its write-up's sha256."""
    loaded = _load(root)
    if loaded is None:
        return 1
    hashes = {wu.slug: wu.flag_sha256 for wu in loaded[1]}
    table = solvers()
    chosen = list(slugs) or sorted(table)
    unknown = [s for s in chosen if s not in table]
    if unknown:
        print(f"no practice solver for: {unknown}", file=sys.stderr)
        return 1
    failed = 0
    for slug in chosen:
        start = time.monotonic()
        result = table[slug]()
        ms = (time.monotonic() - start) * 1000
        ok = hashlib.sha256(result.flag.encode()).hexdigest() == hashes.get(slug)
        failed += not ok
        verdict = "flag matches write-up sha256" if ok else "FAIL: flag does not match the write-up"
        print(f"{slug:<20} {result.queries:>6} queries {ms:>8.1f} ms  {verdict}")
    print(f"{len(chosen) - failed} of {len(chosen)} practice solves verified")
    return 1 if failed else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point."""
    ap = argparse.ArgumentParser(prog="ctfw", description=__doc__)
    ap.add_argument("--root", type=Path, default=Path(), help="repository root (default: current directory)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="validate every write-up")
    ix = sub.add_parser("index", help=f"write {WRITEUPS_DIR}/{INDEX_NAME}")
    ix.add_argument("--check", action="store_true", help="fail if the index is out of date instead of writing it")
    nw = sub.add_parser("new", help="create a write-up skeleton")
    nw.add_argument("slug")
    nw.add_argument("--category", required=True, choices=CATEGORIES)
    nw.add_argument("--technique", action="append", required=True, dest="techniques")
    sv = sub.add_parser("solve", help="run practice solvers and verify their flags")
    sv.add_argument("slugs", nargs="*")
    args = ap.parse_args(argv)
    root: Path = args.root
    if not root.is_dir():
        ap.error(f"--root {root} is not a directory")
    if args.cmd == "check":
        return cmd_check(root)
    if args.cmd == "index":
        return cmd_index(root, args.check)
    if args.cmd == "new":
        return cmd_new(root, args.slug, args.category, args.techniques)
    return cmd_solve(root, args.slugs)


if __name__ == "__main__":
    sys.exit(main())
