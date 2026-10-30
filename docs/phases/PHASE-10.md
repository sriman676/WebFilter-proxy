# Phase 10 - Threat feeds, download hashing and scanning
Milestone: M5 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC_EXT_POLICY.md P3-P4; DECISIONS D-52, D-53, D-54, D-24; RESEARCH R-12, R-13; SPEC 4.6, 4.7; INTERFACES (feeds, scanning); tests/corpus/feed_cases.md; THREAT_MODEL T-55..T-60; TEST_PLAN E-59..E-67, F-14..F-16

## Plan
Tasks: `FeedManager` (fetch with verification and destination policy, conditional GET, caps, per-format parsers, protected-domain and TLD rejection, sanity guard, candidate->active promotion, 5 versions, rollback, expiry, events), feed matching (domain, URL digests, IP) integrated into rules 2/3/4 with `rule_id feed:<name>:...`; CLI `feeds status|update|rollback|test`; record verified feed terms in the addendum. Scanning: eligibility (extension/type/magic), `detect` tee mode and `block` buffered mode with 0600 temp files, hash blocklist, `ClamdScanner` (INSTREAM), optional YARA behind feature `yara`, unscannable/unavailable policies, concurrency/quota limits, startup cleanup of `scan_tmp`, log fields `scan_*`/`body_*`/`download_name`, block page reasons. `docker compose` file for clamd test container (pin tag in ENVIRONMENT.md); EICAR strings are built at test time.
Tests: E-59..E-67, F-14..F-16, P-09, unit tests for parsers, sanity guard, magic detection, clamd framing.

## Pentest gate
PT-10.1 .. PT-10.10 (definitions: docs/PENTEST_PLAN_EXT.md, section "Phase 10")

## Gate checklist
- [ ] `just fmt lint test` green; coverage gates still met; `just ui-lint` / `just docs-check` pass
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p10` executed, manual PT cases done, `docs/pentest/phase-10/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md; shipped config keeps the new features OFF
- [ ] tag `phase-10-complete`; then `/clear`
