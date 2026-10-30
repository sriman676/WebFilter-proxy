# Build Plan (index; the detailed plan of each phase lives in its own brief)

Per-phase detail is NOT duplicated here (single source of truth: `docs/phases/PHASE-N.md`).

## Phase loop (identical for every phase)
1. `git switch -c phase/N-name`. Read the phase brief and ONLY the sections it lists.
2. Plan (plan mode), then implement tests first / alongside. Follow CLAUDE.md rules.
3. Run `just fmt lint test` until green. Run `just cov` for coverage gates when listed.
4. Run `just pentest-pN` (automation) and execute the manual PT cases; write `docs/pentest/phase-N/REPORT.md`
   and `FINDINGS.md`. Run the `security-reviewer` subagent on the phase diff.
5. Fix findings (regression test first), re-run the failed PT cases, update docs/CHANGELOG.
6. Phase gate (all must be true): build+lint+tests green; coverage gates; PT cases all executed and passing;
   zero open Critical/High; docs updated; `git tag phase-N-complete`. Then STOP and report a short summary
   (what was built, test counts, findings fixed/accepted). Do not start the next phase until told to
   (or run `/build-phase N+1`).
Never ask questions: use the documented defaults; log new choices in `docs/DECISIONS_ADDENDUM.md`.

## Milestones (D-35)
- **M1 = Phases 0-3**: the assignment (multi-threaded proxy + client saving named HTML) with filtering and logs. Demoable alone; trace in `docs/ACCEPTANCE.md (Part B)`. Tag `m1-complete`.
- **M2 = Phases 4-5**: TLS interception, Splunk and detections. Tag `m2-complete`.
- **M3 = Phases 6-7**: HTTP/2 inside intercepted TLS, transparent mode (Linux lab). Tag `m3-complete`.
- **M4 = Phase 8**: hardening, compatibility, final regression, acceptance. Tag `m4-complete` (= v1.0 complete).
- **M5 = Phases 9-13 (v1.1)**: policies and limits, feeds and scanning, operations/admin, client enhancements, final regression. Tag `m5-complete`. Features default OFF.
Do not start a milestone before the previous one is tagged. Run `just docs-check` at every gate.

## Phases
| # | Name | Milestone | Brief |
|---|---|---|---|
| 0 | Environment & scaffold | M1 | [phases/PHASE-0.md](phases/PHASE-0.md) |
| 1 | Core library | M1 | [phases/PHASE-1.md](phases/PHASE-1.md) |
| 2 | Proxy server (HTTP + CONNECT tunnel, no interception) - split into 3 sub-phases | M1 | [phases/PHASE-2.md](phases/PHASE-2.md) |
| 3 | Client | M1 | [phases/PHASE-3.md](phases/PHASE-3.md) |
| 4 | TLS interception | M2 | [phases/PHASE-4.md](phases/PHASE-4.md) |
| 5 | Observability, Splunk, detections | M2 | [phases/PHASE-5.md](phases/PHASE-5.md) |
| 6 | HTTP/2 inside intercepted TLS | M3 | [phases/PHASE-6.md](phases/PHASE-6.md) |
| 7 | Transparent mode (Linux lab) | M3 | [phases/PHASE-7.md](phases/PHASE-7.md) |
| 8 | Hardening, performance, full regression, docs | M4 | [phases/PHASE-8.md](phases/PHASE-8.md) |
| 9 | Identity, profiles, rate limits, bandwidth caps, quotas | M5 | [phases/PHASE-9.md](phases/PHASE-9.md) |
| 10 | Threat feeds, download hashing and scanning | M5 | [phases/PHASE-10.md](phases/PHASE-10.md) |
| 11 | Operations: admin listener, metrics, web UI, TUI, access requests, doctor | M5 | [phases/PHASE-11.md](phases/PHASE-11.md) |
| 12 | Client enhancements: input file, retries, resume, snapshot, crawl | M5 | [phases/PHASE-12.md](phases/PHASE-12.md) |
| 13 | Final v1.1 regression and acceptance | M5 | [phases/PHASE-13.md](phases/PHASE-13.md) |

Resuming or starting a session: read `CLAUDE.md`, `docs/INDEX.md`, `docs/STATE.md`, `docs/DECISIONS.md`, then ONLY the current
phase brief. Operator prompts: `README.md (Prompts section)`.

## Definition of Done (project)
- `just acceptance` (see `docs/ACCEPTANCE.md`) passes on a clean Linux checkout, CI green (Linux+macOS; netns job on Linux with sudo).
- All SPEC requirements implemented; every E-xx, I-xx, SM-xx, U-xx, PT-xx recorded as passing.
- Zero open Critical/High findings; Medium accepted or fixed; FINAL_REPORT written.
- 1k-line sample log ingested in Splunk (or documented fallback) with correct fields; detections validated.
- README steps verified on a clean machine. All decisions/addenda documented. SBOM generated.

## Definition of Done (v1.1, after Phase 13)
All of the above for v1.0 plus: every E-53..E-83, PT-9..PT-13 and S-05 recorded as passing; v1.1 features OFF by default and
documented; OPERATIONS drills executed; `just acceptance` includes ACCEPTANCE steps 18-24; tag `m5-complete`.
