# Phase 5 - Observability, OpenSearch, detections
Milestone: M2 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
LOG_SCHEMA, SPEC 4.14 and 8, siem/opensearch/*, A-14, A-35, THREAT_MODEL T-18..T-20,T-35, TEST_PLAN section 8 (S-xx), E-25, E-28, E-30

## Plan
Tasks: finalize system/stats events, rotation hardening, OpenSearch configs (index templates, Fluent Bit, detections
incl. attack-attempt rules), Docker compose (`siem/opensearch/`), dataset generator
(`scripts/siem/gen_test_traffic.py`: benign mix, beaconing, DGA-like, high block rate, attack bursts), docs of detections
(`siem/opensearch/DETECTIONS.md`, outside the D-48 docs cap: logic, thresholds, tuning, false positives).
Tests: E-25, E-28, E-30, S-01..S-04.
Pentest gate: PT-5.1 .. PT-5.7 (purple team: replay attacks, confirm alerts).

## Pentest gate
PT-5.1 .. PT-5.7 (definitions: docs/PENTEST_PLAN.md, section "Phase 5")

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p5` executed, manual PT cases done, `docs/pentest/phase-5/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-5-complete` (and `m2-complete` if this closes the milestone); then `/clear`
