"""The one-format rules for a single write-up and across the tree."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from conftest import SHA, TODAY, VALID, make_tree

from ctf_writeups.techniques import Technique
from ctf_writeups.validate import MAX_BYTES, check_text, check_tree

REL = "writeups/web/example.md"


def problems(text: str, vocab: dict[str, Technique], rel: str = REL) -> list[str]:
    """Problem messages for one text."""
    wu, found = check_text(text, rel, vocab, TODAY)
    assert (wu is None) == bool(found)
    return [p.message for p in found]


def test_a_valid_write_up_passes_and_is_returned(vocab: dict[str, Technique]) -> None:
    wu, found = check_text(VALID, REL, vocab, TODAY)
    assert found == []
    assert wu is not None
    assert (wu.slug, wu.category, wu.techniques, wu.flag_sha256) == ("example", "web", ("sql-injection",), SHA)
    assert wu.summary == ""


@pytest.mark.parametrize(
    ("old", "new", "fragment"),
    [
        ('title = "Example"\n', "", "missing front matter key 'title'"),
        ('title = "Example"\n', 'title = "Example"\nauthor = "me"\n', "unknown front matter key 'author'"),
        ('title = "Example"', 'title = "   "', "'title' must not be empty"),
        ('title = "Example"', "title = 3", "'title' must be a str"),
        ("solved = 2026-11-01", 'solved = "2026-11-01"', "'solved' must be a date"),
        ("solved = 2026-11-01", "solved = 2026-11-01T10:00:00Z", "'solved' must be a date"),
        ("solved = 2026-11-01", "solved = 2026-11-09", "is in the future"),
        ('slug = "example"', 'slug = "Example_1"', "lower-case words"),
        ('slug = "example"', 'slug = "other"', "does not match the file name"),
        ('category = "web"', 'category = "osint"', "'category' must be one of"),
        ('difficulty = "easy"', 'difficulty = "insane"', "'difficulty' must be one of"),
        ('techniques = ["sql-injection"]', "techniques = []", "at least one technique"),
        ('techniques = ["sql-injection"]', 'techniques = "sql-injection"', "'techniques' must be a list"),
        ('techniques = ["sql-injection"]', 'techniques = ["sqli"]', "unknown technique 'sqli'"),
        ('techniques = ["sql-injection"]', "techniques = [1]", "must contain strings"),
        ('techniques = ["sql-injection"]', 'techniques = ["rop", "rop"]', "listed twice"),
        (f'flag_sha256 = "{SHA}"', 'flag_sha256 = "ABC"', "64 lower-case hex"),
        (f'flag_sha256 = "{SHA}"', 'flag_sha256 = ""', "'flag_sha256' must not be empty"),
    ],
)
def test_front_matter_rules(vocab: dict[str, Technique], old: str, new: str, fragment: str) -> None:
    assert old in VALID
    msgs = problems(VALID.replace(old, new, 1), vocab)
    assert any(fragment in m for m in msgs), msgs


@pytest.mark.parametrize(
    ("old", "new", "fragment"),
    [
        ("## Dead ends\n\nGuessing passwords.\n\n", "", "missing section '## Dead ends'"),
        ("## Lesson learned", "## Lessons", "unexpected section '## Lessons'"),
        ("## Lesson learned\n\nUse bound parameters.\n", "## Lesson learned\n\n   \n", "'## Lesson learned' is empty"),
        ("## Recon\n", "# Title\n\n## Recon\n", "no '# ' headings"),
        ("\n## Recon\n", "\nIntro text.\n\n## Recon\n", "text before the first section"),
        (
            "## Lesson learned\n\nUse bound parameters.\n",
            "## Lesson learned\n\nx\n\n## Recon\n\ny\n",
            "appears more than once",
        ),
    ],
)
def test_section_rules(vocab: dict[str, Technique], old: str, new: str, fragment: str) -> None:
    assert old in VALID
    msgs = problems(VALID.replace(old, new, 1), vocab)
    assert any(fragment in m for m in msgs), msgs


def test_sections_out_of_order_are_reported(vocab: dict[str, Technique]) -> None:
    text = VALID.replace("## Recon", "## TMP").replace("## Dead ends", "## Recon").replace("## TMP", "## Dead ends")
    msgs = problems(text, vocab)
    assert any("out of order" in m for m in msgs), msgs


def test_a_heading_inside_code_does_not_count_as_a_section(vocab: dict[str, Technique]) -> None:
    text = VALID.replace("## Dead ends\n\nGuessing passwords.\n", "```\n## Dead ends\n```\n")
    msgs = problems(text, vocab)
    assert "missing section '## Dead ends'" in msgs


def test_every_problem_is_reported_not_just_the_first(vocab: dict[str, Technique]) -> None:
    text = VALID.replace('category = "web"', 'category = "x"').replace("## Exploit", "## Attack")
    msgs = problems(text, vocab)
    assert len(msgs) >= 3


def test_the_real_flag_in_the_text_is_a_spoiler(vocab: dict[str, Technique]) -> None:
    flag = "flag{EXAMPLE-NOT-A-SECRET-test}"
    sha = hashlib.sha256(flag.encode()).hexdigest()
    text = VALID.replace(SHA, sha).replace("Guessing passwords.", f"Got {flag} here.")
    wu, found = check_text(text, REL, vocab, TODAY)
    assert wu is None
    assert [(p.line, p.message) for p in found] == [(19, "the real flag is written out; keep only its sha256")]


def test_a_redacted_or_different_flag_is_allowed(vocab: dict[str, Technique]) -> None:
    text = VALID.replace("Guessing passwords.", "The decoy flag{not-the-one} and flag{...}.")
    assert problems(text, vocab) == []


def test_an_unparseable_file_gives_one_problem(vocab: dict[str, Technique]) -> None:
    assert problems("no front matter", vocab) == ["a write-up must start with a '+++' front matter line"]


def test_tree_accepts_valid_write_ups_and_skips_the_index(tmp_path: Path, vocab: dict[str, Technique]) -> None:
    make_tree(tmp_path, {"web/example.md": VALID, "INDEX.md": "generated"})
    good, found = check_tree(tmp_path, vocab, TODAY)
    assert found == []
    assert [w.path for w in good] == [REL]


def test_tree_requires_the_category_directory(tmp_path: Path, vocab: dict[str, Technique]) -> None:
    make_tree(tmp_path, {"crypto/example.md": VALID, "example.md": VALID})
    good, found = check_tree(tmp_path, vocab, TODAY)
    assert good == []
    assert sorted(p.path for p in found) == ["writeups/crypto/example.md", "writeups/example.md"]
    assert all("must live in writeups/web/example.md" in p.message for p in found)


def test_tree_rejects_duplicate_slugs(tmp_path: Path, vocab: dict[str, Technique]) -> None:
    other = VALID.replace('category = "web"', 'category = "crypto"').replace("sql-injection", "padding-oracle")
    make_tree(tmp_path, {"web/example.md": VALID, "crypto/example.md": other})
    good, found = check_tree(tmp_path, vocab, TODAY)
    assert len(good) == 2
    assert [p.message for p in found] == ["slug 'example' already used by writeups/crypto/example.md"]


def test_empty_or_missing_tree_is_a_problem(tmp_path: Path, vocab: dict[str, Technique]) -> None:
    _, found = check_tree(tmp_path, vocab, TODAY)
    assert [p.message for p in found] == ["directory not found"]
    make_tree(tmp_path, {})
    _, found = check_tree(tmp_path, vocab, TODAY)
    assert [p.message for p in found] == ["no write-ups found"]


def test_oversized_and_non_utf8_files_are_rejected(tmp_path: Path, vocab: dict[str, Technique]) -> None:
    make_tree(tmp_path, {})
    web = tmp_path / "writeups" / "web"
    web.mkdir()
    (web / "big.md").write_bytes(b"x" * (MAX_BYTES + 1))
    (web / "latin.md").write_bytes(b"+++\n\xe9\n+++\n")
    _, found = check_tree(tmp_path, vocab, TODAY)
    msgs = sorted(p.message for p in found)
    assert msgs[0].startswith("file is larger than")
    assert msgs[1].startswith("not UTF-8")


def test_symlinked_write_ups_are_refused(tmp_path: Path, vocab: dict[str, Technique]) -> None:
    make_tree(tmp_path, {"web/example.md": VALID})
    outside = tmp_path / "outside.md"
    outside.write_text(VALID.replace('slug = "example"', 'slug = "link"'), encoding="utf-8")
    try:
        (tmp_path / "writeups" / "web" / "link.md").symlink_to(outside)
    except OSError:
        pytest.skip("creating symbolic links needs extra rights on this system")
    _, found = check_tree(tmp_path, vocab, TODAY)
    assert [p.message for p in found] == ["symbolic links are not allowed"]
