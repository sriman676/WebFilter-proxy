# Phase 8 - Hardening, performance, full regression, docs
Milestone: M4 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
docs/ACCEPTANCE.md, TEST_PLAN sections 6b and 7, DECISIONS D-34, D-39, PENTEST_PLAN Phase 8, VERSIONS (toolchain bump rules)

## Plan
Tasks: real-world compatibility suite (TEST_PLAN C-01..C-09); optional independent review (D-39); fix remaining Mediums; performance work only if D-34 missed; Dockerfile (non-root) + systemd unit
example; complete README (quick start, flags, CA install, ethics, limitations: QUIC/ECH/h2/mTLS/pinning),
ARCHITECTURE section, threat model update, SBOM, release build with feature assertions, `just acceptance`.
Tests: L-01..L-05, C-01..C-09, full E-suite, full regression.
Pentest gate: PT-8.1 .. PT-8.7 and a final report `docs/pentest/FINAL_REPORT.md`.

## Pentest gate
PT-8.1 .. PT-8.7 (definitions: docs/PENTEST_PLAN.md, section "Phase 8")

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p8` executed, manual PT cases done, `docs/pentest/phase-8/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-8-complete` (and `m4-complete` if this closes the milestone); then `/clear`
