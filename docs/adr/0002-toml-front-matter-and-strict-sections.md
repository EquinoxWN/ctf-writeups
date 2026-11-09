# ADR 0002: TOML front matter and exactly four sections

- **Status:** Accepted

## Context

Write-ups need metadata (category, techniques, date, flag hash) that a tool can read, and a body
format that a checker can enforce. Two choices had to be made: the metadata syntax, and how
strict the body format is.

## Decision

- Metadata is TOML between `+++` lines, read with the standard library's `tomllib`. Keys are a
  closed set: unknown keys are errors, so a typo (`techinques`) fails instead of being ignored.
- The body has exactly four level-2 sections, `Recon`, `Dead ends`, `Exploit`, `Lesson learned`,
  each once, in that order, none empty. Level-3 headings inside them are free. No other level-2
  section and no text before `## Recon` is allowed.

## Consequences

- No third-party dependency: the package has an empty `dependencies` list, which keeps the audit
  surface to the dev tools.
- TOML dates are typed values, so `solved` is compared with today's UTC date directly; a quoted
  string date is a type error, not a silent mismatch.
- The cost: Jekyll and Hugo themes default to YAML (`---`), so publishing through a static-site
  generator later (M3) needs Hugo's TOML mode or a conversion step.
- The strict body format rejects useful extras such as a `## References` section. They go inside
  `## Lesson learned` for now; if that proves awkward, an optional trailing section can be added
  without breaking existing write-ups.
- `## Dead ends` is mandatory, which forces writing down failed attempts. That is the point of
  the repository, and the section most often missing from write-ups elsewhere.
