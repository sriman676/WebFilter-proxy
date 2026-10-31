#!/usr/bin/env bash
# E-28, S-01..S-05 against a real OpenSearch (A-14, A-28, A-35). Needs Docker access (docker group).
# 1. start OpenSearch (security ON) with a generated admin password (siem/opensearch/.env, 0600, gitignored)
# 2. run the real proxy with canary-laden requests (S-04), append the labelled dataset, ship with Fluent Bit
# 3. detections over OpenSearch must equal the offline evaluation; no canary is searchable
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SIEM="$ROOT/siem/opensearch"
cd "$SIEM"
docker info >/dev/null 2>&1 || { echo "SIEM-E2E SKIP: no Docker access (add yourself to the docker group)"; exit 2; }

if [ ! -f .env ]; then
  umask 077
  python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("OPENSEARCH_PASSWORD=Wf-"+"".join(secrets.choice(a) for _ in range(24))+"9a!")' > .env
fi
chmod 600 .env
set -a; . ./.env; set +a
COMPOSE=(docker compose --env-file .env)
WORK=$(mktemp -d)
cleanup() {
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
  "${COMPOSE[@]}" --profile ship down -v >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d opensearch
mkdir -p certs
for _ in $(seq 60); do
  "${COMPOSE[@]}" cp opensearch:/usr/share/opensearch/config/root-ca.pem certs/root-ca.pem 2>/dev/null && break
  sleep 2
done
os() { # method path [json-file]: credentials go through a curl config on stdin, never argv
  local args=(-sS --fail-with-body --cacert certs/root-ca.pem -X "$1" "https://localhost:9200$2" -K -)
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' --data-binary "@$3")
  printf 'user = "admin:%s"\n' "$OPENSEARCH_PASSWORD" | curl "${args[@]}"
}
for _ in $(seq 90); do os GET /_cluster/health >/dev/null 2>&1 && break; sleep 2; done
os GET /_cluster/health >/dev/null
os PUT /_index_template/webfilter-requests index-template.json >/dev/null
os PUT /_index_template/webfilter-other index-template-other.json >/dev/null

# Real proxy traffic carrying canaries (S-04, E-30): blocked and SSRF requests need no network.
cargo build --quiet --release --locked --bin webfilter-proxy --manifest-path "$ROOT/Cargo.toml"
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/release/webfilter-proxy"
mkdir -p "$WORK/lab/blocklists" "$WORK/logs"
printf 'canary-blocked.test\n' > "$WORK/lab/blocklists/domains.txt"
: > "$WORK/lab/blocklists/url_patterns.txt"; : > "$WORK/lab/blocklists/ip_blocklist.txt"
printf 'listen = "127.0.0.1:18080"\n[logging]\ndir = "%s"\n' "$WORK/logs" > "$WORK/lab/config.toml"
"$BIN" --config "$WORK/lab/config.toml" run 2>/dev/null & PROXY_PID=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/18080) 2>/dev/null && break; sleep 0.1; done
P=(curl -s -o /dev/null -x http://127.0.0.1:18080)
"${P[@]}" -H 'Cookie: s=CANARYCOOKIE' -H 'Authorization: Bearer CANARYAUTH' -H 'Proxy-Authorization: Basic CANARYPROXY' \
  -d 'password=CANARYBODY' 'http://canary-blocked.test/login?token=CANARYQUERY' || true
"${P[@]}" 'http://127.0.0.1:9/?k=CANARYSSRF' || true
kill -TERM "$PROXY_PID"; wait "$PROXY_PID" 2>/dev/null || true; PROXY_PID=
if grep -rq CANARY "$WORK/logs"; then echo "SIEM-E2E FAIL: canary in proxy logs"; exit 1; fi

python3 "$ROOT/scripts/siem/gen_test_traffic.py" "$WORK/gen" --end "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" >/dev/null
for f in "$WORK"/gen/webfilter*.jsonl; do cat "$f" >> "$WORK/logs/$(basename "$f")"; done
EXPECT=$(cat "$WORK"/logs/webfilter*.jsonl | wc -l)
WEBFILTER_LOG_DIR="$WORK/logs" "${COMPOSE[@]}" --profile ship up -d fluent-bit
for _ in $(seq 120); do
  os POST /webfilter-*/_refresh >/dev/null 2>&1 || true
  N=$(os GET '/webfilter-*/_count' 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])' || echo 0)
  [ "$N" -ge "$EXPECT" ] && break; sleep 2
done
[ "$N" -eq "$EXPECT" ] || { echo "SIEM-E2E FAIL (E-28): indexed $N of $EXPECT events"; exit 1; }

printf '{"query":{"query_string":{"query":"*CANARY*"}}}' > "$WORK/q.json"
HITS=$(os POST '/webfilter-*/_count' "$WORK/q.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
[ "$HITS" -eq 0 ] || { echo "SIEM-E2E FAIL (S-04): $HITS documents contain a canary"; exit 1; }

NOW=$(python3 -c 'import sys; sys.path.insert(0,sys.argv[1]); from common import load_jsonl; print(max(e["timestamp"] for e in load_jsonl(sys.argv[2])))' "$ROOT/scripts/siem" "$WORK/logs")
python3 "$ROOT/scripts/siem/detect.py" --jsonl "$WORK/logs" --now "$NOW" | sort > "$WORK/local.txt"
python3 "$ROOT/scripts/siem/detect.py" --opensearch https://localhost:9200 --ca certs/root-ca.pem --now "$NOW" | sort > "$WORK/remote.txt"
if ! diff -u "$WORK/local.txt" "$WORK/remote.txt"; then echo "SIEM-E2E FAIL (S-02/S-03): OpenSearch results differ"; exit 1; fi
echo "SIEM-E2E PASS ($N events indexed, $(wc -l < "$WORK/remote.txt") alerts, 0 canaries)"
