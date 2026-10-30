# WebFilter Proxy (Rust)

Multi-threaded HTTP/HTTPS forward proxy with blocklists, optional TLS interception and Splunk-ready JSON
logs, plus a client that fetches URLs through the proxy and saves them as named HTML files.

> Status: instruction scaffold. Build it with Claude Code: open this folder with `claude`, paste the
> kickoff prompt from the Prompts section below, and run `/build-phase 0`.

## Planned usage
```bash
cp config/config.example.toml config/config.toml   # hardened defaults; for local-origin experiments use config/demo.toml
cargo run --bin webfilter-proxy -- --config config/config.toml run
cargo run --bin webfilter-client -- https://example.com https://rust-lang.org
# -> output/example.com.html, output/rust-lang.org.html
```
## Documentation map
Start at `docs/INDEX.md` (it lists every document, its purpose and the reading order; docs load progressively, D-47). Gap history: `archive/GAPS_ANALYSIS.md`.

## Prompts for Claude Code
Tips: run `claude` in the repo root; use plan mode per phase; `/clear` after every gate (state lives in docs/STATE.md);
`/compact` if a phase runs long. Commands live in `.claude/commands/`.

### 1. Kickoff (paste once, first session)
```
Read CLAUDE.md, docs/INDEX.md, docs/STATE.md and docs/DECISIONS.md. Then read ONLY docs/phases/PHASE-0.md and the
sections it lists; do not load other docs. Rules: never ask me questions - follow DECISIONS.md and record any new choice
in docs/DECISIONS_ADDENDUM.md. Write tests first, run the phase pentest, fix findings with a regression test first,
run `just docs-check`, update docs/STATE.md and CHANGELOG.md, tag the gate, then stop with a summary of 15 lines or fewer.
Do Phase 0 now.
```

### 2. Each next phase
```
/build-phase 1
```
(then 2 ... 13; phases 9-13 are the v1.1 feature packs). Without slash commands: `Read docs/STATE.md and docs/phases/PHASE-N.md (only those plus the sections it lists), execute the phase including its pentest gate and gate checklist, update STATE.md, stop at the gate.`

### 3. Resume after a context reset, a new day, or a crash
```
/resume
```
Without slash commands: `Read CLAUDE.md, docs/INDEX.md, docs/STATE.md, docs/DECISIONS.md, then the current phase brief. Run git status, git log --oneline -15 and git tag; run just docs-check and just test; continue the phase loop from where it stopped. Do not redo finished work. Do not ask me questions.`

### 4. Gate failed / findings open
```
/phase-gate N
```

### 5. Independent adversarial review (before each milestone tag)
```
Use the security-reviewer subagent on the current phase diff and SPEC rules R1-R15, H1-H11. Return the findings table,
then fix every High/Critical with regression tests.
```

### 6. Docs drift check
```
/gap-check
```

### 7. New Rust stable released (e.g. 1.100)
```
/bump-toolchain 1.100.0
```

### 8. Final acceptance (after Phase 8 for v1.0; after Phase 13 for v1.1)
```
Run docs/ACCEPTANCE.md step by step, write docs/pentest/FINAL_REPORT.md with evidence, fix failures, tag m4-complete (v1.0) or m5-complete (v1.1) only when every step passes.
```
