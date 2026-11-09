#!/usr/bin/env bash
# `just e2e-netns`: E-44..E-50 and PT-7.6/7.8 in the netns lab (Linux, root; D-43). The proxy runs
# as the invoking user (no CAP_NET_ADMIN). Host state (nft ruleset, netns, links) must be identical
# before and after. Usage: sudo -E scripts/e2e_netns.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $(id -u) -eq 0 && -n "${SUDO_USER:-}" ]] || { echo "E2E-NETNS SKIP: run as 'sudo -E just e2e-netns'"; exit 2; }
for tool in ip nft curl python3 openssl; do
  command -v "$tool" >/dev/null || { echo "E2E-NETNS SKIP: $tool missing"; exit 2; }
done
# What the lab could leave behind: nft tables, namespaces, link names (counters/states change on their own).
snapshot() { { nft list tables; ip netns list; ip -o link | awk -F': ' '{print $2}' | sed 's/@.*//' | sort; } 2>/dev/null; }
BEFORE=$(snapshot)
WORK=$(mktemp -d); chown "$SUDO_USER" "$WORK"; PIDS=(); fail=0
cleanup() {
  kill "${PIDS[@]}" 2>/dev/null || true
  "$ROOT/scripts/netns_lab.sh" down >/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
in_ns() { ip netns exec wf-client "$@"; }

WF_PROXY_UID=$(id -u "$SUDO_USER") "$ROOT/scripts/netns_lab.sh" up >/dev/null
"$ROOT/scripts/gen_test_pki.sh" "$WORK/pki" tls.test pass.test >/dev/null
# Test origins on the TEST-NET-1 dummy addresses.
python3 - "$WORK/pki" 2>/dev/null <<'PY' &
import http.server, ssl, sys, threading
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"origin " + self.path.encode()
        self.send_response(200); self.send_header("content-length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
plain = http.server.ThreadingHTTPServer(("192.0.2.10", 80), H)
tls = http.server.ThreadingHTTPServer(("192.0.2.11", 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1] + "/leaf.pem", sys.argv[1] + "/leaf.key")
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
threading.Thread(target=plain.serve_forever, daemon=True).start(); tls.serve_forever()
PY
PIDS+=($!)
mkdir -p "$WORK/lab/blocklists"
printf 'blocked.test\n' > "$WORK/lab/blocklists/domains.txt"
: > "$WORK/lab/blocklists/url_patterns.txt"; : > "$WORK/lab/blocklists/ip_blocklist.txt"
cat > "$WORK/lab/config.toml" <<CFG
listen = "127.0.0.1:18080"
[logging]
dir = "$WORK/logs"
[transparent]
enabled = true
acknowledge_lab_only = true
http_listen = "10.200.0.1:18880"
tls_listen = "10.200.0.1:18443"
[tls]
intercept = true
ca_dir = "$WORK/proxy-ca"
upstream_ca_bundle = "$WORK/pki/ca.pem"
passthrough_domains = ["pass.test"]
CFG
chown -R "$SUDO_USER" "$WORK"
AS_USER=(sudo -u "$SUDO_USER" env "PATH=$PATH" "HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)" "CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}")
"${AS_USER[@]}" bash -c "cd '$ROOT' && cargo build --quiet --locked --features insecure-test --bin webfilter-proxy" || { echo "E2E-NETNS FAIL: build"; exit 1; }
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/webfilter-proxy"
"${AS_USER[@]}" WEBFILTER_TEST_HOSTS="site.test=192.0.2.10,blocked.test=192.0.2.10,other.test=192.0.2.99,tls.test=192.0.2.11,pass.test=192.0.2.11" \
  "$BIN" --config "$WORK/lab/config.toml" run 2>"$WORK/proxy.err" &
PIDS+=($!)
sleep 2
R="--max-time 5 -s -o /dev/null -w %{http_code}"
check "E-44 transparent HTTP allowed"      '[[ $(in_ns curl $R --resolve site.test:80:192.0.2.10 http://site.test/a) == 200 ]]'
check "E-44 blocked domain 403"            '[[ $(in_ns curl $R --resolve blocked.test:80:192.0.2.10 http://blocked.test/) == 403 ]]'
check "E-45 transparent HTTPS intercepted" '[[ $(in_ns curl $R --cacert $WORK/proxy-ca/ca.pem --resolve tls.test:443:192.0.2.11 https://tls.test/x) == 200 ]]'
check "E-46 Host vs original IP (strict)"  '[[ $(in_ns curl $R --resolve other.test:80:192.0.2.10 http://other.test/) == 403 ]]'
check "E-47 no SNI blocked"                '! in_ns curl $R --cacert $WORK/pki/ca.pem https://192.0.2.11/ >/dev/null'
check "E-48 direct connection closed"      '[[ $(in_ns curl $R http://10.200.0.1:18880/) == 000 ]]'
E49=$(in_ns curl $R http://10.200.0.1/)
check "E-49 proxy own IP is not proxied (got $E49)" '[[ $E49 == 403 || $E49 == 508 ]]'
check "E-50 passthrough replays the hello" '[[ $(in_ns curl $R --cacert $WORK/pki/ca.pem --resolve pass.test:443:192.0.2.11 https://pass.test/) == 200 ]]'
check "PT-7.6 QUIC (udp/443) rejected"     'in_ns python3 -c "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect((\"192.0.2.11\",443)); s.send(b\"x\");
try: s.recv(1); sys.exit(1)
except ConnectionRefusedError: sys.exit(0)
except Exception: sys.exit(1)"'
kill "${PIDS[@]}" 2>/dev/null; wait 2>/dev/null; PIDS=()
check "E-44 log fields (transparent, orig_dst, host_verified)" \
  "python3 -c \"import json,sys; ev=[json.loads(l) for l in open('$WORK/logs/webfilter.jsonl')]; sys.exit(0 if any(e['transparent'] and e['orig_dst_ip']=='192.0.2.10' and e['host_verified'] for e in ev) else 1)\""
check "E-48 orig_dst_failed event"         "grep -q orig_dst_failed $WORK/logs/webfilter_system.jsonl"
[[ $E49 == 403 || $E49 == 508 ]] || { echo "  E-49 log:"; grep -h '10.200.0.1' "$WORK"/logs/*.jsonl | tail -3; tail -5 "$WORK/proxy.err"; }
"$ROOT/scripts/netns_lab.sh" down >/dev/null
check "PT-7.8 teardown restores the host exactly" '[[ "$(snapshot)" == "$BEFORE" ]]'
[[ $fail -eq 0 ]] && echo "E2E-NETNS PASS" || { echo "E2E-NETNS FAIL"; exit 1; }
