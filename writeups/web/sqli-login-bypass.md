+++
title = "Login bypass on the practice board"
slug = "sqli-login-bypass"
category = "web"
platform = "ctf-writeups practice set"
event = "Practice set, challenge 1"
solved = 2026-11-08
difficulty = "easy"
techniques = ["sql-injection"]
flag_sha256 = "3753e7b7c9b390ed520ecbed2e0fcad41cd417cbf3736af8ab044781eb4fdd23"
summary = "A login form pastes user input into SQL; a quote and a comment log in as admin."
+++

## Recon

The target is `LoginChallenge.login(name, password)` in
[`src/ctf_writeups/practice/sqli_login.py`](../../src/ctf_writeups/practice/sqli_login.py), an
in-memory SQLite user table behind a login function. It answers one of three pages:
`invalid credentials`, `welcome <name>`, or `database error`. Logging in as `guest` / `guest`
works and shows that a successful login greets the user by the name stored in the database.

A third answer, `database error`, is a strong hint: the application surfaces SQL failures, so
input probably reaches the SQL text.

## Dead ends

- **Guessing the admin password.** `admin` / `admin` returns `invalid credentials`. Guessing is
  slow, noisy, and on a real platform against the rules.
- **Injecting in the password only.** A payload such as `' OR '1'='1` in the password field
  matches the first row of the table, which is `guest`, not `admin`. It proves the injection but
  logs in as the wrong user.

## Exploit

A single quote in the name (`admin'`) produces `database error`, so the name is pasted into a
quoted string. The query is shaped like:

```sql
SELECT name FROM users WHERE name = '<name>' AND password = '<password>'
```

Closing the string and commenting out the rest removes the password check:

```text
name     = admin'--
password = anything
```

The database sees `WHERE name = 'admin'` and returns the admin row; the page prints the flag.
The solver in the same file tries the three inputs above in order and needs 3 attempts:

```bash
ctfw solve sqli-login-bypass
```

## Lesson learned

- An error page that differs from a normal "wrong password" page is itself an oracle; treat it
  as the first finding.
- Choose the injection point that controls which row comes back (the name), not just whether a
  row comes back.
- The fix is bound parameters, not escaping: `login_fixed` uses
  `WHERE name = ? AND password = ?`, and the test suite checks that the same payload fails there.
  Real systems should also store password hashes, never plain text.
