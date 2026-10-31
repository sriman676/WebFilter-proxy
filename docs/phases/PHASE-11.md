# Phase 11 - Operations: admin listener, metrics, web UI, TUI, access requests, doctor
Milestone: M5 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC_EXT_OPS.md (all); DECISIONS D-55..D-59, D-65; RESEARCH R-14, R-15, R-16; SPEC 4.7, 4.13; OPERATIONS.md; tests/corpus/admin_host_cases.tsv and access_request_cases.tsv; THREAT_MODEL T-61..T-68; TEST_PLAN E-68..E-77, C-10, C-11, F-17, F-18

## Plan
Tasks: admin server (hyper, Host allowlist on every route, token auth + lockout, Origin check, security headers, audit log), `/healthz` `/readyz` `/metrics` (hand-written exposition, bounded labels) and `/api/v1/*` with strict JSON schemas and bounded ring/top-N structures; web UI in `assets/admin/` (vanilla JS, textContent only) plus `scripts/ui_lint.py` wired into `just ui-lint`; TUI subcommand (ratatui, sanitized strings, terminal restore); access-request workflow (block-page form, HMAC CSRF, `webfilter.local` virtual host handled before DNS, eligibility rules, rate limits, temp allows persisted atomically, events); `doctor`; new SIEM detections validated; OPERATIONS drills prepared; `just promtool` check.
Tests: E-68..E-77, F-17, F-18, UI/TUI tests (headless browser smoke, ratatui TestBackend), promtool.

## Pentest gate
PT-11.1 .. PT-11.11 (definitions: docs/PENTEST_PLAN_EXT.md, section "Phase 11")

## Gate checklist
- [ ] `just fmt lint test` green; coverage gates still met; `just ui-lint` / `just docs-check` pass
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p11` executed, manual PT cases done, `docs/pentest/phase-11/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md; shipped config keeps the new features OFF
- [ ] tag `phase-11-complete`; then `/clear`
