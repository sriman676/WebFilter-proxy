#!/usr/bin/env bash
# Assignment demo (docs/ACCEPTANCE.md Part B, milestone M1). Local origins only; uses config/demo.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n=== %s\n' "$*"; }
wait_port() { for _ in $(seq 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }

cargo build --release --locked -q
bin=${CARGO_TARGET_DIR:-target}/release
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
mkdir -p "$work/site1" "$work/site2"
echo '<h1>site one</h1><img src="logo.png"><a href="about.html">about</a>' >"$work/site1/index.html"
echo '<h1>about</h1><a href="index.html">home</a><script>alert(1)</script>' >"$work/site1/about.html"
printf '\x89PNG\r\n\x1a\n' >"$work/site1/logo.png"
echo '<h1>site two</h1>' >"$work/site2/index.html"
python3 -m http.server 18081 --bind 127.0.0.1 -d "$work/site1" >/dev/null 2>&1 &
python3 -m http.server 18082 --bind 127.0.0.1 -d "$work/site2" >/dev/null 2>&1 &
wait_port 18081 && wait_port 18082

step "1. Start the proxy (config/demo.toml) - a multi-threaded tokio runtime"
"$bin/webfilter-proxy" --config config/demo.toml run &
proxy=$!
wait_port 18080
echo "proxy pid $proxy, OS threads: $(ps -o nlwp= -p "$proxy" | tr -d ' ')"

client() { "$bin/webfilter-client" --proxy http://127.0.0.1:18080 --out-dir "$work/output" "$@"; }

step "2. Fetch 3 URLs (two local test sites + one blocked by a URL pattern)"
code=0
client http://127.0.0.1:18081/ http://127.0.0.1:18082/index.html http://127.0.0.1:18081/wp-admin/install.php || code=$?
ls -l "$work/output"

step "3. The blocked URL: exit code $code (3 = at least one BLOCKED; the event id is printed above)"

step "4. 50 parallel fetches"
mapfile -t urls < <(seq 1 50 | sed 's|^|http://127.0.0.1:18081/?n=|')
client --jobs 16 -q "${urls[@]}"
echo "files saved: $(find "$work/output" -name '*.html' | wc -l)"

step "5. Last JSON log lines (logs/webfilter.jsonl)"
tail -n 3 logs/webfilter.jsonl

step "6. v1.1 client: offline snapshot and a polite crawl (robots.txt honored, >= 250 ms per host)"
client --snapshot http://127.0.0.1:18081/index.html
client --crawl-depth 1 --max-pages 5 http://127.0.0.1:18081/index.html
find "$work/output" -path '*_files*' -o -name '*_crawl' -o -name '*snapshot_report.json' | sort

step "7. Intercepted HTTPS demo: see Phase 4 (TLS interception)"
kill -INT "$proxy"
wait "$proxy" || true
echo "proxy stopped cleanly"
