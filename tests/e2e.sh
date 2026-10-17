#!/usr/bin/env bash
# End-to-end test against real kernel WireGuard interfaces.
#
# Builds the image and starts four exporters in one network namespace, each
# with a different WG_INTERFACES. A helper container then creates three
# interfaces there and checks that every exporter reports exactly the
# interfaces it was asked for, and never a key.
#
#   wg0  two peers (one with endpoint, preshared key and keepalive; one bare)
#   wg1  one peer
#   wg2  no peers
#
# Needs a Docker host whose kernel has WireGuard (any Linux >= 5.6).
# Honours DOCKER_CONTEXT / DOCKER_HOST.
set -euo pipefail

IMAGE=${IMAGE:-wireguard-exporter:e2e}
HELPER_IMAGE=alpine:3.22
NAME=wireguard-exporter-e2e-$$

cleanup() { docker rm -f "$NAME" "$NAME-one" "$NAME-two" "$NAME-partial" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if [[ -z "${SKIP_BUILD:-}" ]]; then
  docker build -t "$IMAGE" "$(dirname "$0")/.."
fi

# Same hardening as the documented DaemonSet: only NET_ADMIN, read-only root.
HARDENING=(--read-only --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges)
docker run -d --name "$NAME" "${HARDENING[@]}" "$IMAGE" >/dev/null
for spec in one:9587:wg1 two:9588:wg0,wg2 partial:9589:wg2,wg-missing; do
  IFS=: read -r suffix port interfaces <<< "$spec"
  docker run -d --name "$NAME-$suffix" --network "container:$NAME" "${HARDENING[@]}" \
    -e LISTEN_PORT="$port" -e WG_INTERFACES="$interfaces" "$IMAGE" >/dev/null
done

docker run --rm -i --network "container:$NAME" --cap-add NET_ADMIN "$HELPER_IMAGE" sh -s <<'EOF'
set -eu
apk add --no-cache --quiet wireguard-tools iproute2 curl

umask 077
cd /tmp
for i in 0 1 2; do
  wg genkey > "wg$i.key"
  ip link add "wg$i" type wireguard
  wg set "wg$i" private-key "wg$i.key" listen-port "5182$i"
done
for p in a b c; do wg genkey | wg pubkey > "peer-$p.pub"; done
wg genpsk > wg0.psk
wg genpsk > wg1.psk

wg set wg0 peer "$(cat peer-a.pub)" preshared-key wg0.psk \
  allowed-ips 10.99.0.2/32 endpoint 127.0.0.1:51830 persistent-keepalive 25
wg set wg0 peer "$(cat peer-b.pub)" allowed-ips 10.99.0.3/32
wg set wg1 peer "$(cat peer-c.pub)" preshared-key wg1.psk \
  allowed-ips 10.99.1.2/32 endpoint 127.0.0.1:51831
ip addr add 10.99.0.1/24 dev wg0
ip addr add 10.99.1.1/24 dev wg1
for i in 0 1 2; do ip link set "wg$i" up; done
# Queue traffic to the peers with endpoints so their transmit counters move
# (handshake initiations).
ping -c 3 -W 1 10.99.0.2 >/dev/null 2>&1 || true
ping -c 3 -W 1 10.99.1.2 >/dev/null 2>&1 || true

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

# Space-separated, sorted label values of a metric, e.g. "wg0 wg1 ".
values() { sed -n "s/^$2{.*$3=\"\([^\"]*\)\".*/\1/p" "$1" | sort -u | tr '\n' ' '; }
targets() { sed -n 's/^wireguard_scrape_success{target="\([^"]*\)"} \(.*\)$/\1=\2/p' "$1" | sort | tr '\n' ' '; }
expect() { [ "$2" = "$3" ] || fail "$1: got '$2', want '$3'"; }

# check PORT INTERFACES PEER_INTERFACES TARGETS
check() {
  m="metrics-$1"
  for _ in $(seq 1 20); do
    curl -fsS "http://127.0.0.1:$1/metrics" > "$m" 2>/dev/null && break
    sleep 0.5
  done
  [ -s "$m" ] || { fail ":$1 serves no metrics"; return; }
  for secret in wg*.key wg*.psk; do
    grep -qF "$(cat "$secret")" "$m" && fail ":$1 leaks $secret"
  done
  expect ":$1 interfaces" "$(values "$m" wireguard_interface_info interface)" "$2"
  for metric in wireguard_peer_info wireguard_sent_bytes_total wireguard_received_bytes_total \
      wireguard_latest_handshake_seconds wireguard_persistent_keepalive_seconds; do
    expect ":$1 $metric interfaces" "$(values "$m" "$metric" interface)" "$3"
  done
  expect ":$1 scrape_success" "$(targets "$m")" "$4"
}

check 9586 "wg0 wg1 wg2 " "wg0 wg1 " "all=1.0 "
check 9587 "wg1 " "wg1 " "wg1=1.0 "
check 9588 "wg0 wg2 " "wg0 " "wg0=1.0 wg2=1.0 "
check 9589 "wg2 " "" "wg-missing=0.0 wg2=1.0 "

# Per-peer values, from the unfiltered exporter.
m=metrics-9586
a=$(cat peer-a.pub); b=$(cat peer-b.pub); c=$(cat peer-c.pub)
expect "peer count" "$(grep -c '^wireguard_peer_info{' $m)" 3
expect "interface public keys" "$(values $m wireguard_interface_info public_key)" \
  "$(for i in 0 1 2; do wg pubkey < "wg$i.key"; done | sort | tr '\n' ' ')"
grep -q "^wireguard_peer_info{allowed_ips=\"10.99.0.2/32\",endpoint=\"127.0.0.1:51830\",interface=\"wg0\",public_key=\"$a\"} 1.0$" $m \
  || fail "peer a info"
grep -q "^wireguard_peer_info{allowed_ips=\"10.99.0.3/32\",endpoint=\"\",interface=\"wg0\",public_key=\"$b\"} 1.0$" $m \
  || fail "peer b info (no endpoint)"
grep -q "^wireguard_peer_info{allowed_ips=\"10.99.1.2/32\",endpoint=\"127.0.0.1:51831\",interface=\"wg1\",public_key=\"$c\"} 1.0$" $m \
  || fail "peer c info"
grep -q "^wireguard_sent_bytes_total{.*public_key=\"$a\"} [1-9]" $m || fail "peer a sent bytes missing or zero"
grep -q "^wireguard_sent_bytes_total{.*public_key=\"$c\"} [1-9]" $m || fail "peer c sent bytes missing or zero"
grep -q "^wireguard_sent_bytes_total{.*public_key=\"$b\"} 0.0$" $m || fail "peer b sent bytes not zero"
grep -q "^wireguard_persistent_keepalive_seconds{.*public_key=\"$a\"} 25.0$" $m || fail "peer a keepalive"
grep -q "^wireguard_persistent_keepalive_seconds{.*public_key=\"$b\"} 0.0$" $m || fail "peer b keepalive off"
grep -q '^wireguard_interface_info{fwmark="off",interface="wg2",listen_port="51822",' $m || fail "wg2 listen port"

[ "$failures" -eq 0 ] || { echo "e2e: $failures failure(s)" >&2; exit 1; }
echo "e2e: OK"
EOF
