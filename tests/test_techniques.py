"""The technique vocabulary file."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import REPO, VOCAB_TEXT

from ctf_writeups.techniques import CATEGORIES, MAX_VOCAB_BYTES, VocabularyError, load_vocabulary, parse_vocabulary


def test_valid_vocabulary_is_returned_by_id() -> None:
    vocab = parse_vocabulary(VOCAB_TEXT)
    assert sorted(vocab) == ["padding-oracle", "rop", "sql-injection"]
    assert vocab["sql-injection"].cwe == "CWE-89"
    assert vocab["rop"].cwe is None


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("", "no techniques defined"),
        ("[a\n", "not valid TOML"),
        ('[Bad_Id]\nname = "x"\ncategory = "web"\n', "id must be lower-case"),
        ('x = "not a table"\n', "must be a table"),
        ('[a]\nname = ""\ncategory = "web"\n', "'name' must be a non-empty string"),
        ('[a]\nname = "A"\ncategory = "osint"\n', "'category' must be one of"),
        ('[a]\nname = "A"\ncategory = "web"\ncwe = "89"\n', "'cwe' must look like CWE-89"),
        ('[a]\nname = "A"\ncategory = "web"\nurl = "x"\n', "unknown keys ['url']"),
    ],
)
def test_invalid_vocabularies_list_the_problem(text: str, fragment: str) -> None:
    with pytest.raises(VocabularyError) as exc:
        parse_vocabulary(text)
    assert any(fragment in p for p in exc.value.problems), exc.value.problems


def test_all_problems_are_collected() -> None:
    with pytest.raises(VocabularyError) as exc:
        parse_vocabulary('[a]\nname = ""\ncategory = "x"\n[b]\nname = "B"\ncategory = "y"\n')
    assert len(exc.value.problems) == 3


def test_missing_oversized_and_non_utf8_files_fail(tmp_path: Path) -> None:
    with pytest.raises(VocabularyError, match="cannot read"):
        load_vocabulary(tmp_path / "missing.toml")
    big = tmp_path / "big.toml"
    big.write_bytes(b"#" * (MAX_VOCAB_BYTES + 1))
    with pytest.raises(VocabularyError, match="larger than"):
        load_vocabulary(big)
    bad = tmp_path / "bad.toml"
    bad.write_bytes(b"\xff\xfe")
    with pytest.raises(VocabularyError, match="not UTF-8"):
        load_vocabulary(bad)


def test_the_repository_vocabulary_is_valid_and_spans_categories() -> None:
    vocab = load_vocabulary(REPO / "techniques.toml")
    assert len(vocab) >= 10
    assert {t.category for t in vocab.values()} == set(CATEGORIES) - {"misc"}
