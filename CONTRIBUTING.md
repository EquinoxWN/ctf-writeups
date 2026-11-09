# Contributing

Thanks for helping. This is a Python project with Markdown write-ups; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+. Caches and virtual environments stay in git-ignored folders inside the repo.

```bash
make setup   # install the package and dev tools
make lint    # ruff, ruff format, mypy --strict
make test    # full test suite
make check   # every write-up follows the format; the index is current
make solve   # practice solves match their write-ups
make audit   # known-vulnerability check (as in CI)
```

A pull request is ready when these pass and CI is green.

## Adding a write-up

1. If the technique is new, add it to `techniques.toml` (id, name, category, CWE if one fits).
2. `ctfw new <slug> --category <category> --technique <id>` creates `writeups/<category>/<slug>.md`.
3. Fill in the front matter and the four sections. Put the flag's sha256 in `flag_sha256`, never
   the flag itself (`python -c "import hashlib; print(hashlib.sha256(b'flag{...}').hexdigest())"`).
4. Run `ctfw check`, then `ctfw index` to update `writeups/INDEX.md`.

Only write up challenges you may publish: the practice set here, or (from M2) retired challenges
under each platform's rules. Exploits target only challenges shipped in this repository.

## Guidelines

- Keep each change focused; explain the problem it solves in the pull request.
- Add or update a test for every behaviour change, and update `docs/results/` when numbers change.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
