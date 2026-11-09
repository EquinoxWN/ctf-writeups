.PHONY: setup lint test check index solve audit ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev]"

# ruff, ruff format and mypy --strict.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

test:
	$(PY) -m pytest -q -rs

# Every write-up follows the one format, and the technique index is current.
check:
	ctfw check && ctfw index --check

# Rebuild writeups/INDEX.md from the write-ups and techniques.toml.
index:
	ctfw index

# Run the practice solvers and compare each flag with its write-up's sha256.
solve:
	ctfw solve

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

ci: setup lint test check solve
