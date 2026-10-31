#!/usr/bin/env bash
# `just acceptance`: docs/ACCEPTANCE.md steps 1-16 in order; stops at the first FAIL. Steps that need
# missing privileges/tools (netns sudo, Docker, h2spec) report SKIP with the reason (exit code 2).
# FUZZ_SECS (default 60) per fuzz target; SOAK_SECS for the load soak; PENTEST=1 also runs pentest-p1..p8.
set -uo pipefail
cd "$(dirname "$0")/.."
step() { # number name command...
  local n=$1 name=$2; shift 2
  "$@" > "/tmp/wf-acceptance-$n.log" 2>&1; local rc=$?
  case $rc in
    0) echo "PASS  $n $name" ;;
    2) echo "SKIP  $n $name ($(tail -1 "/tmp/wf-acceptance-$n.log"))" ;;
    *) echo "FAIL  $n $name (see /tmp/wf-acceptance-$n.log)"; exit 1 ;;
  esac
}
netns() { sudo -n true 2>/dev/null || { echo "needs sudo: sudo -E just e2e-netns"; return 2; }; sudo -E scripts/e2e_netns.sh; }
step 1 "environment" just check-env
step 2 "docs consistency" just docs-check
step 3 "static quality" bash -c "just fmt && just lint && just audit"
step 4 "tests" just test
step 5 "coverage" just cov
step 6 "fuzz smoke" just fuzz-smoke "${FUZZ_SECS:-60}"
step 7 "end-to-end" just e2e
step 8 "netns e2e" netns
step 9a "SIEM offline" just siem-test
step 9b "SIEM OpenSearch" just siem-e2e
step 10 "HTTP/2 conformance" just h2spec
if [[ "${PENTEST:-0}" == 1 ]]; then
  for p in 0 1 2 3 4 5 6 7; do step "11.$p" "pentest-p$p" just "pentest-p$p"; done
fi
step 12 "load and soak" just load
step 13 "compatibility" just compat
step 14 "assignment demo" just demo
step 16 "release audit" just release-audit
echo "ACCEPTANCE PASS (manual: step 15 clean-machine README, step 17 independent review, C-06 browsers)"
