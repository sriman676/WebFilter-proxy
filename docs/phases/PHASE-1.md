# Phase 1 - Core library
Milestone: M1 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC 4.5 (canonicalization), 4.6 (filtering + blocklist grammar), 4.11 (limits), 5.3 (naming), 6 (config), 7; INTERFACES (normalize, blocklist, policy, filter, logger, naming); LOG_SCHEMA; tests/corpus/*; THREAT_MODEL T-03,T-14,T-18..T-20,T-27; DECISIONS D-09,D-11,D-12,D-15..D-18

## Plan
Tasks: `normalize` (4.5), `blocklist` (4.6 grammar, limits, hot reload with arc-swap), `filter` (rule order),
`policy` (dest/port/loop), `logger` + `system log` + `stats` structs, `naming` (5.3), full `config`
(SPEC 6) incl. auth hash types, `blocklist test` subcommand skeleton.
Tests: U-001..055, U-fn-*, U-cfg, U-blocklist, U-policy, U-logger, U-auth, P-01..P-06, F-01..F-03 targets,
coverage gates. Deliverable: library usable without sockets.
Pentest gate: PT-1.1 .. PT-1.8.

## Pentest gate
PT-1.1 .. PT-1.8 (definitions: docs/PENTEST_PLAN.md, section "Phase 1")

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p1` executed, manual PT cases done, `docs/pentest/phase-1/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-1-complete` (and `m1-complete` if this closes the milestone); then `/clear`
