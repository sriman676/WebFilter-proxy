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
## HTTPS interception (optional, lab only)
> **Ethics and scope (D-30, D-68):** interception decrypts other people's traffic. Only intercept your own
> devices or users who were told, on your own machine or lab. Never install the CA on machines you do not own.
> Banking/health/government sites should stay in `tls.passthrough_domains`.

1. In `config/config.toml` set `[tls] intercept = true` (default `ca_dir = "~/.webfilter"`).
2. `webfilter-proxy --config config/config.toml ca generate` creates `ca.pem` (public) and `ca.key` (0600,
   never share or commit it). The proxy refuses to start if the key is group/world-readable, a symlink,
   or owned by another user.
3. `webfilter-proxy --config config/config.toml ca export > webfilter-ca.pem`
4. **Firefox only (recommended, A-28):** Settings -> Privacy & Security -> Certificates -> View Certificates ->
   Authorities -> Import -> `webfilter-ca.pem` -> tick "Trust this CA to identify websites". Firefox keeps
   its own store, so no other application trusts the CA. Set Firefox's manual proxy to `127.0.0.1:8080`
   for HTTP and HTTPS, and disable HTTP/3 (`network.http.http3.enable = false`): QUIC/UDP bypasses a TCP proxy (D-21).
5. To undo: delete the CA in the same Firefox dialog, then delete `~/.webfilter/`.
6. Command-line check: `webfilter-client --ca-cert webfilter-ca.pem https://example.com`.

Upstream certificates are always verified (D-20); an invalid origin certificate gives `502 upstream_cert_invalid`.
For manual experiments, `scripts/gen_test_pki.sh <dir> <host...>` creates a throwaway test PKI.

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
