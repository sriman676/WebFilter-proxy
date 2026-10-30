# Phase 12 - Client enhancements: input file, retries, resume, snapshot, crawl
Milestone: M5 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC_EXT_CLIENT.md (all); SPEC 5 (base client); DECISIONS D-60..D-62; RESEARCH R-16; tests/corpus/snapshot_html_cases.md and robots_cases.tsv; THREAT_MODEL T-69..T-71; TEST_PLAN E-78..E-82, F-19..F-22

## Plan
Tasks: `--input-file`, dedupe and caps; retry/backoff with Retry-After handling and the never-retry list; JSONL manifest with lock file and `--resume`; optional `--resume-partial` with If-Range; snapshot (lol_html rewriting, asset planning and caps, sanitization and CSP meta, safe asset names, `snapshot_report.json`); crawl (BFS, robots.txt parser, politeness, trap caps, `index.html`, link rewriting); JSON output additions; docs in README; demo script extended.
Tests: E-78..E-82, F-19..F-22, unit tests for rewriters, robots, retry math, manifest verification.

## Pentest gate
PT-12.1 .. PT-12.8 (definitions: docs/PENTEST_PLAN_EXT.md, section "Phase 12")

## Gate checklist
- [ ] `just fmt lint test` green; coverage gates still met; `just ui-lint` / `just docs-check` pass
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p12` executed, manual PT cases done, `docs/pentest/phase-12/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md; shipped config keeps the new features OFF
- [ ] tag `phase-12-complete`; then `/clear`
