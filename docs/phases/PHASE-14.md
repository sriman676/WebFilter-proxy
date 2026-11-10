# Phase 14 - Browser extension and WASM rule plugins
Milestone: M5 (A-30) | Prerequisite: Phase 13 gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
SPEC_EXT_OPS.md O1, O3, O9, O10; DECISIONS_ADDENDUM A-30, A-45, A-46; THREAT_MODEL T-75, T-76; TEST_PLAN E-84..E-88, F-23

## Plan
Tasks: `[admin] readonly_token_hash`; `extension/` (MV3 manifest, background worker, popup, options; Chrome and
Firefox); `just ext-lint`; `src/plugins.rs` behind the `plugins` feature (wasmtime, fuel and memory limits, no
imports, fresh instance per call, request view JSON); evaluation hook after local rules; `/api/v1/plugins` and
metrics; example plugin `plugins/examples/block_keyword.wat`; README sections; config example (commented).
Tests: E-84..E-88, F-23, unit tests for the request view and option validation.

## Pentest gate
PT-14.1 .. PT-14.7 (definitions: docs/PENTEST_PLAN_EXT.md, section "Phase 14")

## Gate checklist
- [ ] `just fmt lint test` green; `just plugins-test`, `just ext-lint`, `just ui-lint`, `just docs-check` pass
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p14` written; pentest runs in the consolidated final run (A-29)
- [ ] CHANGELOG.md and `docs/STATE.md` updated; decisions in DECISIONS_ADDENDUM.md; plugins and extension OFF by default
- [ ] tag `phase-14-complete`
