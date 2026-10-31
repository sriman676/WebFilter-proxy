# End-to-End Acceptance Runbook (`just acceptance` automates steps 1-9)

Run on a clean Linux checkout (sudo available for step 8). Every step must print PASS; any FAIL stops the run.
Record results in `docs/pentest/FINAL_REPORT.md`.

| # | Step | Command | Expected |
|---|---|---|---|
| 1 | Environment | `just check-env` | all tools present, versions printed |
| 2 | Docs consistency | `just docs-check` | no dangling IDs; every threat has tests; size budgets; toolchain pins agree; all 9 phase briefs valid |
| 3 | Static quality | `just fmt lint audit` | fmt/clippy clean; deny/audit/geiger clean; 0 first-party unsafe (except documented D-41 exception, if any) |
| 4 | Unit/property/integration | `just test` | all pass; includes U-001..055, filename oracle, SM-01..25, I-*, I-h2-*, I-transparent-* |
| 5 | Coverage | `just cov` | >= 85% on core modules, >= 70% overall |
| 6 | Fuzz smoke + differential | `just fuzz-smoke` | F-01..F-12, X-01..X-03: no crash/disagreement |
| 7 | End-to-end (real binaries) | `just e2e` | E-01..E-43 (except E-28 -> step 9, E-41 -> step 10), E-51, E-52 pass |
| 8 | Network-namespace e2e | `just e2e-netns` | E-44..E-50 pass; teardown leaves host unchanged (PT-7.8) |
| 9 | SIEM (OpenSearch, A-14) | `just siem-test` and `just siem-e2e` | E-28 and S-01..S-05 pass (`siem-test` is the Docker-less fallback) |
| 10 | HTTP/2 conformance | `just h2spec` | 0 mandatory failures (E-41) |
| 11 | Pentest suites | `just pentest-p1 ... pentest-p8` | every PT case recorded PASS; no open Critical/High |
| 12 | Load and soak | `just load` | D-34 targets; L-05 soak stable |
| 13 | Compatibility | follow TEST_PLAN C-01..C-09 | results in `docs/COMPATIBILITY.md` |
| 14 | Assignment demo | `scripts/demo.sh` | matches `docs/ACCEPTANCE.md (Part B)` demo steps |
| 15 | Clean-machine README check | follow README in a fresh VM/container | every command works as written (PT-8.6) |
| 16 | Release audit | `just sbom` + release build checks | `insecure-test` OFF, SBOM generated, gitleaks clean |
| 17 | Independent review (optional, D-39) | human or Burp manual session | recorded in FINAL_REPORT |
Final: tags `m1-complete` .. `m4-complete` exist; CHANGELOG complete; FINAL_REPORT written.

## v1.1 additions (Phases 9-13; run after the v1.0 steps above)
| # | Step | Command | Expected |
|---|---|---|---|
| 18 | Policies and limits | `just e2e` (E-53..E-58) | profiles resolve correctly; limits, quotas, shaping behave per spec |
| 19 | Feeds and scanning | `just feeds-test`, `just scan-e2e` (Docker clamd) | E-59..E-67 pass; EICAR blocked/detected; clean files byte-identical |
| 20 | Admin and UI | `just e2e` (E-68..E-71, E-73..E-77), `just ui-e2e` (E-72, E-80), `just ui-lint`, `just promtool` | admin hardened; metrics valid; UI inert on hostile data; access-request flow works |
| 21 | Client features | `just e2e` (E-78, E-79, E-81, E-82) and `just ui-e2e` (E-80) | batch, retry, resume, snapshot, crawl pass |
| 22 | Interactions and performance | E-83, `just load` with features on | no safety bypass; overhead <= 10 percent |
| 23 | Runbook drills | `docs/OPERATIONS.md` drills 1-7 | each works as written |
| 24 | v1.1 pentests | `just pentest-p9` .. `pentest-p13` | all PT-9..PT-13 cases PASS; no open Critical/High |
Final: tag `m5-complete`; FINAL_REPORT updated for v1.1.

## Part B - Assignment trace and demo (milestone M1)
Original assignment: *Multi-threaded Proxy Server and Client. The server accepts any URL from the client, fetches
the output and returns it to the client. The client saves the output as an HTML page with an appropriate name.*
(Extended with filtering, logging, TLS interception and OpenSearch.)

| Requirement | Where implemented | Proof |
|---|---|---|
| Multi-threaded proxy server | tokio multi-thread runtime, one task per connection, `worker_threads` (D-04, SPEC 4.1/4.11) | E-14 (200 concurrent), L-01/L-02, `/proc` or `ps -L` thread count in demo |
| Server accepts ANY URL | absolute-form HTTP requests + CONNECT for https (SPEC 4.2/4.9); only policy-blocked targets refused | E-01, E-02, E-03 |
| Fetches and returns the output | forward + stream response (SPEC 4.2 steps 10-11) | I-01, E-01 |
| Client sends URL via standard proxy protocol | `webfilter-client` with `--proxy` (SPEC 5) | E-01 |
| Client saves output as an HTML page with an appropriate name | naming algorithm (SPEC 5.3), atomic no-clobber write | `filename_cases.tsv`, P-02, E-29 |
| Handles multiple clients simultaneously | concurrency + limits | E-14, PT-2.11 |

### Demo script (Claude Code creates `scripts/demo.sh` in Phase 3; prints each step)
1. start proxy (loopback, port from config) and show its worker thread count; 2. fetch 3 URLs with the client
(two local test origins + one blocked) and list `output/`; 3. show the blocked one: exit code 3 + event id;
4. run 50 parallel client fetches and show all saved; 5. `tail` the JSON log; 6. (M2) intercepted https demo.
The demo uses only local origins and `config/demo.toml` (the hardened `config.example.toml` would refuse loopback origins and non-standard ports).

### Optional report outline (if your course needs a write-up)
Problem and requirements -> architecture diagram (SPEC 3) -> concurrency model -> protocol handling (HTTP proxy,
CONNECT) -> client naming scheme -> security considerations (THREAT_MODEL) -> testing evidence (TEST_PLAN results)
-> pentest summary -> limitations (QUIC, ECH, h2, pinning) -> references (RESEARCH).
