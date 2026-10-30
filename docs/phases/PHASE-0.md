# Phase 0 - Environment & scaffold
Milestone: M1 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
CLAUDE.md, docs/ENVIRONMENT.md, docs/ENVIRONMENT.md, SPEC section 10 (repo conventions), DECISIONS D-02, D-27, D-28, D-35, D-46..D-49

## Plan
Tasks: install/verify tools (ENVIRONMENT.md, ENVIRONMENT.md); the files `rust-toolchain.toml`, `Cargo.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.editorconfig`, `.gitattributes`, `LICENSE` already exist - do NOT run `cargo init`; create stub `src/lib.rs` and the two `src/bin/*.rs` so `cargo check` works, fix any schema/lint-name issues in the provided config files (record in the addendum); add approved crates with `cargo add` and fill the resolved-versions table in ENVIRONMENT.md; pick and record the dated nightly for fuzzing;
lints are configured in Cargo.toml (`unsafe_code=forbid`, clippy deny of unwrap/expect/indexing/panic outside tests); `justfile` with all targets in SPEC 10 (unimplemented ones print a clear TODO and exit 1);
`scripts/check_env.sh`; `deny.toml`; `.github/workflows/ci.yml`; pre-commit hook; `config.rs` skeleton +
`check-config`; empty fuzz package; harness crate skeleton `tests/common`; `CHANGELOG.md`.
Tests: U-cfg basic. Deliverable: `just check-env`, `just lint test` pass.
Pentest gate P0 (light): `cargo deny/audit` clean; `gitleaks` clean; confirm `.gitignore` covers keys/logs/output.

## Pentest gate
light gate: `cargo deny`, `cargo audit`, gitleaks, `.gitignore` coverage

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p0` executed, manual PT cases done, `docs/pentest/phase-0/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-0-complete` (and `m1-complete` if this closes the milestone); then `/clear`
