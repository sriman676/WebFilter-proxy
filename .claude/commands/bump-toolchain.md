---
description: Bump the pinned Rust toolchain safely
argument-hint: <new version, e.g. 1.100.0>
---
Follow docs/ENVIRONMENT.md rule 4 on branch `chore/toolchain-$ARGUMENTS`. First confirm $ARGUMENTS is the current stable from the
official Rust release blog (record the date). Change `rust-toolchain.toml`, `Cargo.toml rust-version`, `clippy.toml msrv` and
`RUST_PIN` in ENVIRONMENT.md together; fix new lints; run `just docs-check` and `just acceptance`; update CHANGELOG.md and
docs/STATE.md. Do not bump crates in the same change.
