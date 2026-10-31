# Phase 9 - Identity, profiles, rate limits, bandwidth caps, quotas
Milestone: M5 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC_EXT_POLICY.md P1-P2; DECISIONS D-50, D-51, D-14; SPEC 4.2 (pipeline), 4.10, 4.11; INTERFACES (v1.1 identity/limits); LOG_SCHEMA new fields; THREAT_MODEL T-51..T-54; TEST_PLAN E-53..E-58, P-07, P-08, L-06, F-13

## Plan
Tasks: `[[users]]`/`[[clients]]`/`[[profiles]]` config and validation (`default` profile, longest-prefix CIDR trie, per-user argon2id); `PolicySet` with hot reload (SIGHUP/mtime, parse-then-swap); `resolve_identity` (per request; IPv4-mapped folding; IPv6 /64 keys; XFF ignored); pipeline step 3b; `Limiter` (token buckets on monotonic clock, bounded LRU 100k, saturating math) for requests/s, connections, in-flight, tunnels, daily quota, up/down bandwidth shapers (shared per-client bucket, 10 ms quanta, throttle counts as activity); 429/503 + `Retry-After`; limits enforced in monitor mode; `client_id`/`profile`/`throttled` log fields; per-profile counters in stats; username/user-enumeration hardening; config sections; SIEM detection additions are done in Phase 11.
Tests: E-53..E-58, P-07, P-08, F-13 target, limiter property tests, unit tests for CIDR/profile resolution and token math; re-run SM and E-19/E-20 regressions with multi-user auth.

## Pentest gate
PT-9.1 .. PT-9.9 (definitions: docs/PENTEST_PLAN_EXT.md, section "Phase 9")

## Gate checklist
- [ ] `just fmt lint test` green; coverage gates still met; `just ui-lint` / `just docs-check` pass
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p9` executed, manual PT cases done, `docs/pentest/phase-9/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md; shipped config keeps the new features OFF
- [ ] tag `phase-9-complete`; then `/clear`
