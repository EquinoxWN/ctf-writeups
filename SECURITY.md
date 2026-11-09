# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/ctf-writeups/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** the `ctfw` checker and index writer (unsafe file handling, path or link escapes,
  unbounded input), the PNG parser's bounds, and any write-up that reveals a live challenge's flag
  or a real secret.
- **Out of scope:** the practice challenges in `src/ctf_writeups/practice/` are vulnerable on
  purpose (string-built SQL, a padding oracle, repeating-key XOR). They run in-process, hold only
  fake `EXAMPLE-NOT-A-SECRET` values, and are never exposed on a network.

## Rules for content

- Exploits run only against the practice targets this repository ships, never against third-party
  hosts.
- Write-ups store a flag's sha256, never the flag; `ctfw check` rejects a write-up that contains it.
- Every key, token or password in the repository is an obviously fake placeholder.

## How this repository protects itself

- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, tests, the write-up checks and a known-vulnerability check (pip-audit) on every push and pull request.
