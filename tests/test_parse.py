import pytest
from prometheus_client import CollectorRegistry, generate_latest

from main import WireGuardCollector, parse_dump

PRIVATE_KEY = "cHJpdmF0ZS1rZXktbXVzdC1uZXZlci1sZWFrLTAwMDA="
PRESHARED_KEY = "cHJlc2hhcmVkLWtleS1tdXN0LW5ldmVyLWxlYWstMDA="

ALL_DUMP = (
    f"wg0\t{PRIVATE_KEY}\tSRVpub0000000000000000000000000000000000000=\t51820\toff\n"
    f"wg0\tPEERa000000000000000000000000000000000000000=\t{PRESHARED_KEY}\t192.0.2.10:51820\t10.0.0.7/32\t1792215300\t1024\t2048\t25\n"
    "wg0\tPEERb000000000000000000000000000000000000000=\t(none)\t(none)\t(none)\t0\t0\t0\toff\n"
)


def test_parse_all_dump():
    interfaces, peers = parse_dump(ALL_DUMP)
    assert [i.name for i in interfaces] == ["wg0"]
    assert interfaces[0].listen_port == 51820
    first, second = peers
    assert first.endpoint == "192.0.2.10:51820"
    assert first.allowed_ips == "10.0.0.7/32"
    assert (first.latest_handshake, first.receive_bytes, first.transmit_bytes) == (1792215300, 1024, 2048)
    assert first.persistent_keepalive == 25
    assert (second.endpoint, second.allowed_ips, second.persistent_keepalive) == ("", "", 0)


def test_parse_single_interface_dump():
    single = "\n".join(line.split("\t", 1)[1] for line in ALL_DUMP.splitlines())
    interfaces, peers = parse_dump(single, "wg0")
    assert interfaces[0].name == "wg0"
    assert {p.interface for p in peers} == {"wg0"}


def test_parse_rejects_unknown_line_without_echoing_it():
    with pytest.raises(ValueError) as exc:
        parse_dump(f"wg0\t{PRIVATE_KEY}\n")
    assert PRIVATE_KEY not in str(exc.value)


class FakeCollector(WireGuardCollector):
    def __init__(self, outputs):
        super().__init__("wg", list(outputs), 1)
        self.outputs = outputs

    def _dump(self, interface):
        output = self.outputs[interface]
        if isinstance(output, Exception):
            raise output
        return parse_dump(output, interface)


def test_metrics_never_contain_secrets():
    single = "\n".join(line.split("\t", 1)[1] for line in ALL_DUMP.splitlines())
    registry = CollectorRegistry()
    registry.register(FakeCollector({"wg0": single, "wg-missing": RuntimeError("no such device")}))
    text = generate_latest(registry).decode()
    assert PRIVATE_KEY not in text
    assert PRESHARED_KEY not in text
    assert 'wireguard_sent_bytes_total{allowed_ips="10.0.0.7/32",interface="wg0",public_key="PEERa000000000000000000000000000000000000000="} 2048.0' in text
    assert 'wireguard_scrape_success{target="wg0"} 1.0' in text
    assert 'wireguard_scrape_success{target="wg-missing"} 0.0' in text
