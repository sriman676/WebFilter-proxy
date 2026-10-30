---
description: Run the end-to-end suite and report failures against TEST_PLAN IDs
---
Run `just e2e` (real proxy + client binaries, offline harness). Map every failure to its E-xx ID in
docs/TEST_PLAN.md, fix root causes (regression test first), and re-run until green. Report pass/fail per ID.
