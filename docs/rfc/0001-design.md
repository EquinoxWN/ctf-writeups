# RFC 0001: ctf-writeups design

- **Status:** Accepted (M1 built)
- **Author:** EquinoxWN
- **Created:** 2026-11-08

## Problem

Capture-the-flag write-ups are useful to a reader (and to an interviewer) only when they show the
reasoning: what was looked at, what failed, what worked and what it teaches. Most personal
write-up collections drift: some are a single exploit script, some skip the failed attempts, some
paste the flag, and there is no way to find "every padding oracle I have solved" without reading
them all. Nothing checks the format, so it decays as the collection grows.

**Users:** the author (writing and finding past solutions), readers learning a technique, and
reviewers judging how the author thinks.

### Critical-to-quality measures (Define)

| CTQ | Target in M1 | How it is measured |
|---|---|---|
| Every write-up has the four sections, in order, non-empty | 100% of write-ups | `ctfw check` exits 0; CI gate |
| Every write-up is indexed by at least one known technique | 100% | `ctfw check` (unknown or missing techniques fail) |
| The index matches the write-ups | always | `ctfw index --check`; CI gate and a test |
| No flag written out in a write-up | 0 spoilers | spoiler rule in `ctfw check` (hash comparison) |
| A practice write-up's claimed flag is the one its solve recovers | 4 of 4 | `ctfw solve` compares sha256 values |
| Rule violations reported with file and line, all at once | every rule | unit tests per rule |

## Goals

- One format for every write-up: TOML front matter plus exactly four sections, `## Recon`,
  `## Dead ends`, `## Exploit`, `## Lesson learned`, enforced by a checker.
- A controlled technique vocabulary (`techniques.toml`, with CWE ids where one fits) and a
  generated index of write-ups by technique, with counts per category.
- Write-ups whose claims are tested: a set of practice challenges shipped in the repo, each with
  a solver that attacks only the challenge's public interface, and the write-up's flag hash
  compared with the solver's result.

## Non-goals

- Publishing write-ups of live challenges (M2 adds the "retired only" rule per platform).
- pwntools exploit scripts against real binaries (M2).
- A rendered site or skill matrix over time (M3).
- Running anything against third-party hosts. The practice targets are in-process Python objects
  with obviously fake flags (`flag{EXAMPLE-NOT-A-SECRET-...}`).

## Design

```
techniques.toml ──► load_vocabulary ──┐
writeups/<category>/<slug>.md ──► parse (front matter + sections) ──► check_text ──► check_tree ──► ctfw check
                                                                                         │
                                                                                         ├──► render_index ──► writeups/INDEX.md (atomic write)
                                                                                         └──► ctfw solve ◄── practice solvers (sqli, CBC oracle, XOR, PNG)
```

- **Parser (`parse.py`):** front matter between `+++` lines, parsed with the standard library's
  `tomllib` (dates become real `date` values). Headings are found outside fenced code blocks, so
  a `## ` line inside a code sample is not a section. CRLF files read the same as LF.
- **Rules (`validate.py`):** exact key set and types; slug equals the file name and the file lives
  in `writeups/<category>/`; category and difficulty from fixed lists; techniques non-empty,
  unique and defined in the vocabulary; `solved` not after today in UTC; `flag_sha256` is 64 hex
  characters; the four sections exactly once, in order, non-empty; no `# ` heading and no text
  before the first section; no flag-shaped string whose sha256 equals `flag_sha256`. Files are
  read as strict UTF-8 with a 256 KiB cap; symbolic links are refused. All problems are
  reported, each with file and line.
- **Index (`index.py`):** deterministic Markdown (sorted by technique name, then category and
  slug), category counts, and the techniques not covered yet. Written through a temp file and
  `os.replace`.
- **CLI (`cli.py`):** `ctfw check`, `ctfw index [--check]`, `ctfw new` (a skeleton that fails the
  check until filled in; never overwrites), `ctfw solve`. Exit 0 on success, 1 on problems, 2 on
  usage errors.
- **Practice set (`practice/`):** a login with string-built SQL, a CBC padding oracle over a toy
  Feistel block cipher (standard library only), a repeating-key XOR note with a known header, and
  a PNG with a decoy text chunk and the flag in a compressed `zTXt` chunk.

## Alternatives considered

| Option | Why not |
|---|---|
| YAML front matter (Jekyll/Hugo style) | Needs PyYAML, and YAML's implicit typing turns `no` into `false` and accepts dates in several shapes. TOML is in the standard library since Python 3.11 and has one date syntax. See [ADR 0002](../adr/0002-toml-front-matter-and-strict-sections.md). |
| A Markdown linter (markdownlint) with custom rules | Checks Markdown style well but knows nothing about the front matter, the technique vocabulary, the index or flag hashes; the rules would be split across two tools and a Node toolchain. |
| Free-form tags instead of a vocabulary | Tags drift (`sqli`, `sql-injection`, `SQLi`) and split the index. A vocabulary costs one line in `techniques.toml` per new technique. |
| Write-ups of real platform challenges from day one | Each platform has its own publication rules (retired boxes only, no flags); checking those is M2 work. The practice set gives M1 write-ups whose exploits can be run and verified in CI. |
| AES from the `cryptography` package for the padding oracle | Adds a compiled dependency for a target where the attack never looks at the cipher. The toy Feistel cipher keeps the repo dependency-free; the write-up says so. |

## Measurement plan (Measure, Analyze, Control)

- **Measure:** `ctfw check` output (write-ups, techniques covered, problems), `ctfw solve` output
  (queries and time per solve), pytest counts. Recorded in [docs/results/m1.md](../results/m1.md).
- **Analyze:** each rule has a test that breaks it on purpose; hand mutations of the core
  functions (see [docs/quality/2026-11-01.md](../quality/2026-11-01.md)) check that the tests
  can fail.
- **Control:** CI runs lint, types, tests, `ctfw check`, `ctfw index --check`, `ctfw solve` and
  `pip-audit` on every push.

## Milestones

- **M1:** Every write-up follows one format. Challenges are indexed by technique.
- **M2:** Exploit scripts use pwntools and are runnable. Only retired challenges are published, following each platform's rules.
- **M3:** An indexed README links every write-up by category and technique. A skill matrix shows progress over time.

## Risks and open questions

- The four sections may be too rigid for some challenges (for example a pure trivia question).
  The rule can grow an allowed optional section; the order check would stay.
- The spoiler rule only finds the flag when it appears verbatim. A flag split across lines or
  encoded would pass; reviewers still read the write-up.
- Practice challenges are written by the author, so they are easier to explain than real ones.
  M2 adds retired platform challenges.
