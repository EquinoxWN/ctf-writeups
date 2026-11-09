"""Shared fixtures: a valid write-up, a small vocabulary and a temporary repository tree."""

from __future__ import annotations

import datetime as dt
import shutil
from pathlib import Path

import pytest

from ctf_writeups.techniques import Technique, parse_vocabulary

REPO = Path(__file__).resolve().parents[1]
TODAY = dt.date(2026, 11, 8)
SHA = "a" * 64

VOCAB_TEXT = """
[sql-injection]
name = "SQL injection"
category = "web"
cwe = "CWE-89"

[padding-oracle]
name = "Padding oracle"
category = "crypto"

[rop]
name = "ROP"
category = "pwn"
"""

VALID = f"""+++
title = "Example"
slug = "example"
category = "web"
platform = "practice"
event = "Example event"
solved = 2026-11-01
difficulty = "easy"
techniques = ["sql-injection"]
flag_sha256 = "{SHA}"
+++

## Recon

Looked at the login form.

## Dead ends

Guessing passwords.

## Exploit

```sql
## not a heading inside code
SELECT 1;
```

### Payload

admin'--

## Lesson learned

Use bound parameters.
"""


@pytest.fixture
def vocab() -> dict[str, Technique]:
    """Three-technique vocabulary."""
    return parse_vocabulary(VOCAB_TEXT)


def make_tree(root: Path, files: dict[str, str], vocab_text: str = VOCAB_TEXT) -> Path:
    """Write techniques.toml and the given write-ups under root."""
    (root / "techniques.toml").write_text(vocab_text, encoding="utf-8")
    (root / "writeups").mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        p = root / "writeups" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


@pytest.fixture
def repo_copy(tmp_path: Path) -> Path:
    """A copy of this repository's write-ups and vocabulary."""
    shutil.copy(REPO / "techniques.toml", tmp_path / "techniques.toml")
    shutil.copytree(REPO / "writeups", tmp_path / "writeups")
    return tmp_path
