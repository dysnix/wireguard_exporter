"""Prometheus exporter for WireGuard peer statistics.

Each scrape runs `wg show <interface> dump` (or `wg show all dump`) and turns
the output into per-peer metrics. The dump contains secrets: the interface
private key and the per-peer preshared key. Both are dropped by field position
right after splitting a line and are never stored, exported or logged.
"""

import logging
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

from prometheus_client import start_http_server
from prometheus_client.core import REGISTRY, CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector

log = logging.getLogger("wireguard_exporter")


@dataclass(frozen=True)
class Interface:
    name: str
    public_key: str
    listen_port: int
    fwmark: str


@dataclass(frozen=True)
class Peer:
    interface: str
    public_key: str
    endpoint: str
    allowed_ips: str
    latest_handshake: int
    receive_bytes: int
    transmit_bytes: int
    persistent_keepalive: int


def _keepalive(value: str) -> int:
    return 0 if value == "off" else int(value)


def parse_dump(text: str, interface: str | None = None) -> tuple[list[Interface], list[Peer]]:
    """Parse `wg show all dump` output, or `wg show <interface> dump` output
    when `interface` is given (that form has no leading interface column).

    Interface line: [iface] private-key public-key listen-port fwmark
    Peer line:      [iface] public-key preshared-key endpoint allowed-ips
                    latest-handshake rx-bytes tx-bytes persistent-keepalive
    """
    interfaces: list[Interface] = []
    peers: list[Peer] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        fields = line.split("\t")
        if interface is not None:
            fields.insert(0, interface)
        if len(fields) == 5:
            name, _private_key, public_key, listen_port, fwmark = fields
            interfaces.append(Interface(name, public_key, int(listen_port), fwmark))
        elif len(fields) == 9:
            name, public_key, _preshared_key, endpoint, allowed_ips, handshake, rx, tx, keepalive = fields
            peers.append(
                Peer(
                    interface=name,
                    public_key=public_key,
                    endpoint="" if endpoint == "(none)" else endpoint,
                    allowed_ips="" if allowed_ips == "(none)" else allowed_ips,
                    latest_handshake=int(handshake),
                    receive_bytes=int(rx),
                    transmit_bytes=int(tx),
                    persistent_keepalive=_keepalive(keepalive),
                )
            )
        else:
            # Never log the line itself: it may hold a key.
            raise ValueError(f"line {lineno}: unexpected field count {len(fields)}")
    return interfaces, peers


class WireGuardCollector(Collector):
    def __init__(self, wg_binary: str, interfaces: list[str], timeout: float):
        self.wg_binary = wg_binary
        self.interfaces = interfaces
        self.timeout = timeout

    def _dump(self, interface: str | None) -> tuple[list[Interface], list[Peer]]:
        args = [self.wg_binary, "show", interface or "all", "dump"]
        result = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"{' '.join(args)} exited {result.returncode}: {result.stderr.strip()}")
        return parse_dump(result.stdout, interface)

    def _read(self) -> tuple[list[Interface], list[Peer], dict[str, bool]]:
        interfaces: list[Interface] = []
        peers: list[Peer] = []
        success: dict[str, bool] = {}
        for name in self.interfaces or [None]:
            target = name or "all"
            try:
                found_interfaces, found_peers = self._dump(name)
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                log.warning("reading %s failed: %s", target, exc)
                success[target] = False
                continue
            interfaces += found_interfaces
            peers += found_peers
            success[target] = True
        return interfaces, peers, success

    def collect(self):
        started = time.monotonic()
        interfaces, peers, success = self._read()

        scrape_success = GaugeMetricFamily(
            "wireguard_scrape_success",
            "Whether reading the WireGuard dump succeeded (target is an interface name or 'all').",
            labels=["target"],
        )
        for target, ok in success.items():
            scrape_success.add_metric([target], 1 if ok else 0)
        yield scrape_success

        interface_info = GaugeMetricFamily(
            "wireguard_interface_info",
            "WireGuard interface metadata.",
            labels=["interface", "public_key", "listen_port", "fwmark"],
        )
        for itf in interfaces:
            interface_info.add_metric([itf.name, itf.public_key, str(itf.listen_port), itf.fwmark], 1)
        yield interface_info

        peer_labels = ["interface", "public_key", "allowed_ips"]
        peer_info = GaugeMetricFamily(
            "wireguard_peer_info",
            "WireGuard peer metadata; endpoint is kept off the counters because it can roam.",
            labels=peer_labels + ["endpoint"],
        )
        received = CounterMetricFamily(
            "wireguard_received_bytes",
            "Bytes received from the peer.",
            labels=peer_labels,
        )
        sent = CounterMetricFamily(
            "wireguard_sent_bytes",
            "Bytes sent to the peer.",
            labels=peer_labels,
        )
        handshake = GaugeMetricFamily(
            "wireguard_latest_handshake_seconds",
            "Unix time of the latest handshake with the peer; 0 if none yet.",
            labels=peer_labels,
        )
        keepalive = GaugeMetricFamily(
            "wireguard_persistent_keepalive_seconds",
            "Persistent keepalive interval for the peer; 0 if off.",
            labels=peer_labels,
        )
        for peer in peers:
            values = [peer.interface, peer.public_key, peer.allowed_ips]
            peer_info.add_metric(values + [peer.endpoint], 1)
            received.add_metric(values, peer.receive_bytes)
            sent.add_metric(values, peer.transmit_bytes)
            handshake.add_metric(values, peer.latest_handshake)
            keepalive.add_metric(values, peer.persistent_keepalive)
        yield peer_info
        yield received
        yield sent
        yield handshake
        yield keepalive

        duration = GaugeMetricFamily(
            "wireguard_scrape_duration_seconds",
            "Time spent reading the WireGuard dump.",
        )
        duration.add_metric([], time.monotonic() - started)
        yield duration


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    listen_addr = os.environ.get("LISTEN_ADDR", "0.0.0.0")
    listen_port = int(os.environ.get("LISTEN_PORT", "9586"))
    interfaces = [name.strip() for name in os.environ.get("WG_INTERFACES", "").split(",") if name.strip()]
    collector = WireGuardCollector(
        wg_binary=os.environ.get("WG_BINARY", "wg"),
        interfaces=interfaces,
        timeout=float(os.environ.get("WG_TIMEOUT", "5")),
    )
    REGISTRY.register(collector)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    start_http_server(listen_port, addr=listen_addr)
    log.info(
        "listening on %s:%d, interfaces: %s",
        listen_addr,
        listen_port,
        ",".join(interfaces) or "all",
    )
    stop.wait()


if __name__ == "__main__":
    main()
