"""The ctfw command: exit codes, messages and files written."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import VALID, make_tree

from ctf_writeups.cli import main


def run(root: Path, *args: str) -> int:
    """Run ctfw against a root."""
    return main(["--root", str(root), *args])


def test_check_passes_on_a_valid_tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_tree(tmp_path, {"web/example.md": VALID})
    assert run(tmp_path, "check") == 0
    assert "1 write-ups OK, 1 of 3 techniques covered, 0 problems" in capsys.readouterr().out


def test_check_fails_with_file_and_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_tree(tmp_path, {"web/example.md": VALID.replace("## Exploit", "## Attack")})
    assert run(tmp_path, "check") == 1
    err = capsys.readouterr().err
    assert "writeups/web/example.md:21: unexpected section '## Attack'" in err
    assert "CHECK FAILED" in err


def test_check_fails_on_a_broken_vocabulary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_tree(tmp_path, {"web/example.md": VALID}, vocab_text="[x]\n")
    assert run(tmp_path, "check") == 1
    assert "techniques.toml: x: 'name' must be a non-empty string" in capsys.readouterr().err


def test_index_writes_then_check_detects_drift(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_tree(tmp_path, {"web/example.md": VALID})
    assert run(tmp_path, "index", "--check") == 1
    assert run(tmp_path, "index") == 0
    assert run(tmp_path, "index", "--check") == 0
    index = tmp_path / "writeups" / "INDEX.md"
    index.write_text(index.read_text(encoding="utf-8") + "edit", encoding="utf-8")
    assert run(tmp_path, "index", "--check") == 1
    assert "out of date" in capsys.readouterr().err


def test_index_is_not_written_when_a_write_up_is_invalid(tmp_path: Path) -> None:
    make_tree(tmp_path, {"web/example.md": VALID.replace("## Recon", "## Intro")})
    assert run(tmp_path, "index") == 1
    assert not (tmp_path / "writeups" / "INDEX.md").exists()


def test_new_creates_a_skeleton_that_fails_check_until_filled(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make_tree(tmp_path, {"web/example.md": VALID})
    assert run(tmp_path, "new", "rop-chain", "--category", "pwn", "--technique", "rop") == 0
    path = tmp_path / "writeups" / "pwn" / "rop-chain.md"
    text = path.read_text(encoding="utf-8")
    assert 'techniques = ["rop"]' in text
    assert run(tmp_path, "check") == 1
    err = capsys.readouterr().err
    assert "'flag_sha256' must not be empty" in err
    assert "section '## Recon' is empty" in err


def test_new_refuses_to_overwrite_or_accept_bad_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_tree(tmp_path, {"web/example.md": VALID})
    before = (tmp_path / "writeups" / "web" / "example.md").read_bytes()
    assert run(tmp_path, "new", "example", "--category", "web", "--technique", "rop") == 1
    assert (tmp_path / "writeups" / "web" / "example.md").read_bytes() == before
    assert run(tmp_path, "new", "Bad Slug", "--category", "web", "--technique", "rop") == 1
    assert run(tmp_path, "new", "ok", "--category", "web", "--technique", "nope") == 1
    err = capsys.readouterr().err
    assert "already exists" in err
    assert "invalid slug" in err
    assert "unknown techniques: ['nope']" in err


def test_usage_errors_exit_2(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--root", str(tmp_path / "missing"), "check"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["--root", str(tmp_path), "new", "x", "--category", "osint", "--technique", "rop"])
    assert exc.value.code == 2


def test_solve_verifies_every_practice_flag(repo_copy: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo_copy, "solve") == 0
    assert "4 of 4 practice solves verified" in capsys.readouterr().out


def test_solve_fails_when_a_write_up_hash_is_wrong(repo_copy: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = repo_copy / "writeups" / "web" / "sqli-login-bypass.md"
    text = path.read_text(encoding="utf-8")
    start = text.index('flag_sha256 = "') + len('flag_sha256 = "')
    path.write_text(text[:start] + "0" * 64 + text[start + 64 :], encoding="utf-8")
    assert run(repo_copy, "solve", "sqli-login-bypass") == 1
    assert "FAIL: flag does not match" in capsys.readouterr().out


def test_solve_rejects_unknown_slugs(repo_copy: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo_copy, "solve", "nope") == 1
    assert "no practice solver for: ['nope']" in capsys.readouterr().err
