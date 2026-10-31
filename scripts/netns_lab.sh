#!/usr/bin/env bash
# Transparent-mode lab (SPEC 4.17, D-43; Linux, root). Idempotent. Creates ONLY:
#   netns wf-client, veth wf-veth0 (host, 10.200.0.1/24, fd00:200::1/64) <-> wf-veth1 (netns, .2/::2),
#   dummy link wf-origin with 192.0.2.10/32 and 192.0.2.11/32 (TEST-NET-1 test origins),
#   nft table inet wf_lab: tcp/80,443 arriving on wf-veth0 -> the transparent listeners (IPv4+IPv6),
#   udp/443 from the lab rejected (forces QUIC clients back to TCP), proxy uid exempt on output.
# `down` removes exactly these; no rule outside table wf_lab is ever touched.
# Usage: sudo scripts/netns_lab.sh up|down|status   (env: WF_HTTP_PORT, WF_TLS_PORT, WF_PROXY_UID)
set -euo pipefail
NS=wf-client; HOST_IF=wf-veth0; NS_IF=wf-veth1; ORIGIN_IF=wf-origin; TABLE=wf_lab
HTTP_PORT=${WF_HTTP_PORT:-18880}; TLS_PORT=${WF_TLS_PORT:-18443}; PROXY_UID=${WF_PROXY_UID:-${SUDO_UID:-0}}
[[ $(id -u) -eq 0 ]] || { echo "netns_lab: run with sudo" >&2; exit 2; }

up() {
  ip netns list | grep -qx "$NS\( .*\)\?" || ip netns add "$NS"
  if ! ip link show "$HOST_IF" >/dev/null 2>&1; then
    ip link add "$HOST_IF" type veth peer name "$NS_IF" netns "$NS"
  fi
  ip addr replace 10.200.0.1/24 dev "$HOST_IF"
  ip -6 addr replace fd00:200::1/64 dev "$HOST_IF" nodad
  ip link set "$HOST_IF" up
  ip netns exec "$NS" ip addr replace 10.200.0.2/24 dev "$NS_IF"
  ip netns exec "$NS" ip -6 addr replace fd00:200::2/64 dev "$NS_IF" nodad
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip link set "$NS_IF" up
  ip netns exec "$NS" ip route replace default via 10.200.0.1
  ip netns exec "$NS" ip -6 route replace default via fd00:200::1
  ip link show "$ORIGIN_IF" >/dev/null 2>&1 || ip link add "$ORIGIN_IF" type dummy
  ip addr replace 192.0.2.10/32 dev "$ORIGIN_IF"
  ip addr replace 192.0.2.11/32 dev "$ORIGIN_IF"
  ip link set "$ORIGIN_IF" up
  nft delete table inet "$TABLE" 2>/dev/null || true
  nft -f - <<NFT
table inet $TABLE {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$HOST_IF" tcp dport 80 redirect to :$HTTP_PORT
    iifname "$HOST_IF" tcp dport 443 redirect to :$TLS_PORT
  }
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "$HOST_IF" udp dport 443 reject
  }
  chain output {
    type nat hook output priority -100; policy accept;
    meta skuid $PROXY_UID accept comment "proxy uid exempt: its own traffic is never redirected"
  }
}
NFT
  echo "netns_lab: up (listeners must bind 10.200.0.1:$HTTP_PORT and 10.200.0.1:$TLS_PORT)"
}

down() {
  nft delete table inet "$TABLE" 2>/dev/null || true
  ip link del "$ORIGIN_IF" 2>/dev/null || true
  ip link del "$HOST_IF" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  echo "netns_lab: down"
}

status() {
  ip netns list | grep -x "$NS\( .*\)\?" || echo "no netns $NS"
  ip -br addr show "$HOST_IF" 2>/dev/null || echo "no $HOST_IF"
  ip -br addr show "$ORIGIN_IF" 2>/dev/null || echo "no $ORIGIN_IF"
  nft list table inet "$TABLE" 2>/dev/null || echo "no table $TABLE"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
