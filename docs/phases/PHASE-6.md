# Phase 6 - HTTP/2 inside intercepted TLS
Milestone: M3 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC 4.16, DECISIONS D-06,D-40,D-45, RESEARCH R-01, R-10, THREAT_MODEL T-37..T-42, TEST_PLAN I-h2-*, E-37..E-43

## Plan
Tasks: `read_client_hello`, ALPN mirroring (D-40), h2 server/client roles on the `h2` crate with our validation layer
(H1-H11), `FloodGuard` (D-45) and `[http2]` config, per-stream pipeline reuse, block response over h2, stats/`h2_flood`
events, h2c rejection on all listeners, `RawH2Client` + h2spec/socat harness, fuzz target F-10, log fields.
Tests: I-h2-valid, I-h2-flood, E-37..E-43, F-10, plus re-run of inner-pipeline tests over h2.
Pentest gate: PT-6.1 .. PT-6.10.

## Pentest gate
PT-6.1 .. PT-6.10 (definitions: docs/PENTEST_PLAN.md, section "Phase 6")

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p6` executed, manual PT cases done, `docs/pentest/phase-6/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-6-complete` (and `m3-complete` if this closes the milestone); then `/clear`
