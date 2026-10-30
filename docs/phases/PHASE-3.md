# Phase 3 - Client
Milestone: M1 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC 5 (all), docs/ACCEPTANCE.md (Part B), DECISIONS D-25,D-26,D-38; TEST_PLAN E-01..E-14,E-29; T-27..T-30

## Plan
Tasks: hyper-based client (D-25/26): URL intake, manual CONNECT with block detection, redirect handling,
size/time caps, naming + atomic no-clobber write, `--json`, exit codes, proxy auth via env/file, subprocess
`ClientRunner`.
Tests: U-fn-*, P-02, F-05/F-06, I-client-tls, E-01, E-02, E-04, E-12, E-13, E-14, E-29 and client-related E-17.
Pentest gate: PT-3.1 .. PT-3.8.

Also: `scripts/demo.sh` (uses `config/demo.toml`, prints each step per ASSIGNMENT_TRACE).

## Pentest gate
PT-3.1 .. PT-3.8 (definitions: docs/PENTEST_PLAN.md, section "Phase 3")

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p3` executed, manual PT cases done, `docs/pentest/phase-3/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-3-complete` (and `m1-complete` if this closes the milestone); then `/clear`
