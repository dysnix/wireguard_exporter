#!/usr/bin/env bash
# End-to-end test against a real kernel WireGuard interface.
#
# Builds the image, starts the exporter, then creates wg0 inside the
# exporter's network namespace from a helper container and checks /metrics.
# Needs a Docker host whose kernel has WireGuard (any Linux >= 5.6).
# Honours DOCKER_CONTEXT / DOCKER_HOST.
set -euo pipefail

IMAGE=${IMAGE:-wireguard-exporter:e2e}
HELPER_IMAGE=alpine:3.22
NAME=wireguard-exporter-e2e-$$

cleanup() { docker rm -f "$NAME" "$NAME-filtered" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if [[ -z "${SKIP_BUILD:-}" ]]; then
  docker build -t "$IMAGE" "$(dirname "$0")/.."
fi

# Same hardening as the documented DaemonSet: only NET_ADMIN, read-only root.
HARDENING=(--read-only --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges)
docker run -d --name "$NAME" "${HARDENING[@]}" "$IMAGE" >/dev/null
docker run -d --name "$NAME-filtered" --network "container:$NAME" "${HARDENING[@]}" \
  -e LISTEN_PORT=9587 -e WG_INTERFACES=wg0,wg-missing "$IMAGE" >/dev/null

docker run --rm -i --network "container:$NAME" --cap-add NET_ADMIN "$HELPER_IMAGE" sh -s <<'EOF'
set -eu
apk add --no-cache --quiet wireguard-tools iproute2 curl

umask 077
wg genkey > /tmp/private
wg genkey | wg pubkey > /tmp/peer
wg genpsk > /tmp/psk

ip link add wg0 type wireguard
wg set wg0 private-key /tmp/private listen-port 51820 \
  peer "$(cat /tmp/peer)" preshared-key /tmp/psk \
  allowed-ips 10.99.0.2/32 endpoint 127.0.0.1:51821 persistent-keepalive 25
ip addr add 10.99.0.1/24 dev wg0
ip link set wg0 up
# Queue traffic to the peer so the transmit counter moves (handshake initiations).
ping -c 3 -W 1 10.99.0.2 >/dev/null 2>&1 || true

fail() { echo "FAIL: $*" >&2; exit 1; }
peer=$(cat /tmp/peer)

for port in 9586 9587; do
  for _ in $(seq 1 20); do
    curl -fsS "http://127.0.0.1:$port/metrics" > "/tmp/metrics-$port" 2>/dev/null && break
    sleep 0.5
  done
  [ -s "/tmp/metrics-$port" ] || fail "no metrics on :$port"
  grep -qF "$(cat /tmp/private)" "/tmp/metrics-$port" && fail "private key leaked on :$port"
  grep -qF "$(cat /tmp/psk)" "/tmp/metrics-$port" && fail "preshared key leaked on :$port"
  grep -qF "$(wg pubkey < /tmp/private)" "/tmp/metrics-$port" || fail "interface public key missing on :$port"
done

m=/tmp/metrics-9586
grep -q '^wireguard_scrape_success{target="all"} 1.0$' $m || fail "scrape of all failed"
grep -q "^wireguard_sent_bytes_total{allowed_ips=\"10.99.0.2/32\",interface=\"wg0\",public_key=\"$peer\"} [1-9]" $m \
  || fail "sent bytes missing or zero"
grep -q "^wireguard_peer_info{allowed_ips=\"10.99.0.2/32\",endpoint=\"127.0.0.1:51821\",interface=\"wg0\",public_key=\"$peer\"} 1.0$" $m \
  || fail "peer info missing"
grep -q "^wireguard_persistent_keepalive_seconds{.*public_key=\"$peer\"} 25.0$" $m || fail "keepalive missing"

m=/tmp/metrics-9587
grep -q '^wireguard_scrape_success{target="wg0"} 1.0$' $m || fail "filtered scrape of wg0 failed"
grep -q '^wireguard_scrape_success{target="wg-missing"} 0.0$' $m || fail "missing interface not reported"
grep -q 'target="all"' $m && fail "filtered exporter read all interfaces"

echo "e2e: OK"
EOF
