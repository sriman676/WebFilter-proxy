# Phase 13 - Final v1.1 regression and acceptance
Milestone: M5 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
docs/ACCEPTANCE.md (v1.1 section); PENTEST_PLAN_EXT.md Phase 13; OPERATIONS.md drills; DECISIONS D-34, D-39, D-63; TEST_PLAN L-06, L-07, E-83

## Plan
Tasks: feature-interaction matrix (E-83), v1.0-to-v1.1 upgrade test, performance regression with features on, SBOM/deny/audit refresh, runbook drills, optional independent review, README/CHANGELOG finalization, `just acceptance` extended with the v1.1 steps, `docs/pentest/FINAL_REPORT.md` updated.
Tests: full E-suite, L-06, L-07, S-05, C-10, C-11.

## Pentest gate
PT-13.1 .. PT-13.7 (definitions: docs/PENTEST_PLAN_EXT.md, section "Phase 13")

## Gate checklist
- [ ] `just fmt lint test` green; coverage gates still met; `just ui-lint` / `just docs-check` pass
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p13` executed, manual PT cases done, `docs/pentest/phase-13/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md; shipped config keeps the new features OFF
- [ ] tag `phase-13-complete` and `m5-complete`; then `/clear`
