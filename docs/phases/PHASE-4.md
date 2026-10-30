# Phase 4 - TLS interception
Milestone: M2 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC 4.9, DECISIONS D-19..D-22, D-44; RESEARCH R-02, R-05; THREAT_MODEL T-06,T-21..T-25; TEST_PLAN harness TestPki

## Plan
Tasks: `ca generate/export`, CA store with perms/zeroize, leaf minting + cache, TLS peek (TLS vs non-TLS),
intercepted pipeline (inner requests run full 4.2 pipeline), upstream rustls config (D-20), SNI/Host/CONNECT
checks (D-22), ECH detection (D-21), passthrough list, `insecure-test` feature (tests only), `scripts/gen_test_pki.sh`,
README CA install steps (manual, ethics warning).
Tests: U-tls, I-ca-perms, E-03, E-06, E-17, E-18, E-27, E-34, TLS parts of E-26 and E-30.
Pentest gate: PT-4.1 .. PT-4.10 (re-run PT-2.x inside tunnel).

## Pentest gate
PT-4.1 .. PT-4.10 (definitions: docs/PENTEST_PLAN.md, section "Phase 4")

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p4` executed, manual PT cases done, `docs/pentest/phase-4/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-4-complete` (and `m2-complete` if this closes the milestone); then `/clear`
