# Phase 7 - Transparent mode (Linux lab)
Milestone: M3 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC 4.17, DECISIONS D-41..D-44, RESEARCH R-05, R-11, ENVIRONMENT (transparent lab), THREAT_MODEL T-43..T-49, TEST_PLAN E-44..E-51

## Plan
Tasks: `OriginalDst` impls (SoOriginalDst via `nix` or conntrack fallback, Fixed for tests), transparent HTTP and TLS
listeners (4.17), host verification, no-SNI/ECH actions, passthrough with ClientHello replay, direct-connection and loop
rejection, `acknowledge_lab_only` validation, `scripts/netns_lab.sh` (setup/teardown/idempotent, table `inet wf_lab`, veth +
netns `wf-client`, uid exemption, QUIC reject rule, IPv4+IPv6), `just e2e-netns`, test-only feature items (D-44), README lab section.
Tests: I-transparent-http/tls, E-44..E-51, F-11, F-12.
Pentest gate: PT-7.1 .. PT-7.9.

## Pentest gate
PT-7.1 .. PT-7.9 (definitions: docs/PENTEST_PLAN.md, section "Phase 7")

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p7` executed, manual PT cases done, `docs/pentest/phase-7/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-7-complete` (and `m3-complete` if this closes the milestone); then `/clear`
