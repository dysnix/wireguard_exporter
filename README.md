# wireguard_exporter

Prometheus exporter for WireGuard peer statistics. On every scrape it runs
`wg show all dump` (or `wg show <interface> dump` for each configured
interface) and exports per-peer traffic counters and handshake times.

The dump carries secrets: the interface private key and each peer's preshared
key. Both are dropped by field position as soon as a line is split; they are
never exported or logged. The end-to-end test asserts this against a real
interface.

## Metrics

| Metric | Type | Labels |
|---|---|---|
| `wireguard_sent_bytes_total` | counter | `interface`, `public_key`, `allowed_ips` |
| `wireguard_received_bytes_total` | counter | `interface`, `public_key`, `allowed_ips` |
| `wireguard_latest_handshake_seconds` | gauge, Unix time (0 = never) | `interface`, `public_key`, `allowed_ips` |
| `wireguard_persistent_keepalive_seconds` | gauge (0 = off) | `interface`, `public_key`, `allowed_ips` |
| `wireguard_peer_info` | gauge, always 1 | `interface`, `public_key`, `allowed_ips`, `endpoint` |
| `wireguard_interface_info` | gauge, always 1 | `interface`, `public_key`, `listen_port`, `fwmark` |
| `wireguard_scrape_success` | gauge | `target` (interface name or `all`) |
| `wireguard_scrape_duration_seconds` | gauge | |

The byte and handshake metric names match
[MindFlavor/prometheus_wireguard_exporter](https://github.com/MindFlavor/prometheus_wireguard_exporter),
so dashboards built for it keep working. `endpoint` is only on
`wireguard_peer_info`, because a roaming peer would otherwise churn every series.

Sample output:

```
wireguard_scrape_success{target="all"} 1.0
wireguard_interface_info{fwmark="off",interface="wg0",listen_port="51820",public_key="Dqbf6fxamt2iqdWG+enIeJO7O5iXw6d6gHbaESLHQDs="} 1.0
wireguard_peer_info{allowed_ips="10.99.0.2/32",endpoint="127.0.0.1:51821",interface="wg0",public_key="uoupDmNz4lWXR4ir2TAOUuorsZ8WC9nXxQKuMogM6n0="} 1.0
wireguard_sent_bytes_total{allowed_ips="10.99.0.2/32",interface="wg0",public_key="uoupDmNz4lWXR4ir2TAOUuorsZ8WC9nXxQKuMogM6n0="} 148.0
wireguard_received_bytes_total{allowed_ips="10.99.0.2/32",interface="wg0",public_key="uoupDmNz4lWXR4ir2TAOUuorsZ8WC9nXxQKuMogM6n0="} 0.0
wireguard_latest_handshake_seconds{allowed_ips="10.99.0.2/32",interface="wg0",public_key="uoupDmNz4lWXR4ir2TAOUuorsZ8WC9nXxQKuMogM6n0="} 0.0
```

Useful queries:

```promql
# Seconds since the last handshake (WireGuard re-handshakes every ~2 min while traffic flows)
time() - wireguard_latest_handshake_seconds > 0

# A peer we keep sending to while nothing comes back
rate(wireguard_sent_bytes_total[5m]) > 0 and rate(wireguard_received_bytes_total[5m]) == 0
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WG_INTERFACES` | empty (all interfaces) | Comma-separated interfaces to read, e.g. `wg0,wg1` |
| `LISTEN_ADDR` | `0.0.0.0` | Address to listen on |
| `LISTEN_PORT` | `9586` | Port to listen on |
| `WG_BINARY` | `wg` | Path to the `wg` tool |
| `WG_TIMEOUT` | `5` | Seconds before a `wg show` call is abandoned |
| `LOG_LEVEL` | `INFO` | Python log level |

## Running

The exporter must run in the network namespace that owns the interfaces and
needs `CAP_NET_ADMIN`: the kernel only returns WireGuard device state to
processes holding it.

```sh
docker run --rm --network host --cap-add NET_ADMIN \
  -e WG_INTERFACES=wg0 ghcr.io/dysnix/wireguard_exporter:latest
curl -s localhost:9586/metrics | grep ^wireguard_
```

Kubernetes DaemonSet essentials:

```yaml
spec:
  template:
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      tolerations:
        - operator: Exists
      containers:
        - name: wireguard-exporter
          image: ghcr.io/dysnix/wireguard_exporter:0.1.0
          env:
            - name: WG_INTERFACES
              value: wg0
          ports:
            - name: metrics
              containerPort: 9586
          securityContext:
            # root is needed: Kubernetes does not grant ambient capabilities,
            # so a non-root process would not hold NET_ADMIN.
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
              add: [NET_ADMIN]
```

## Development

```sh
uv run pytest            # unit tests
tests/e2e.sh             # builds the image and tests it against a real wg interface
```

`tests/e2e.sh` needs a Docker host whose kernel has WireGuard (Linux 5.6 or
newer); it honours `DOCKER_CONTEXT` and `DOCKER_HOST`.

Releases: push a `vX.Y.Z` tag. CI publishes `ghcr.io/dysnix/wireguard_exporter`
as `X.Y.Z`, `X.Y` and `sha-<short>`; pushes to `main` also update `latest`.
