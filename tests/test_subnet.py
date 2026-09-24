import asyncio
import ipaddress

import pytest

from realityprobe.subnet import Neighbor, candidate_domains, neighbor_network, scan_subnet
from conftest import TLSServer, http_ok_handler


def test_neighbor_network():
    assert str(neighbor_network("95.216.10.20")) == "95.216.10.0/24"
    assert str(neighbor_network("95.216.10.20", 22)) == "95.216.8.0/22"
    with pytest.raises(ValueError):
        neighbor_network("2a01:4f8::1")
    with pytest.raises(ValueError):
        neighbor_network("1.2.3.4", 8)


def test_scan_finds_local_tls_host(cert_files):
    _, cp, kp = cert_files
    with TLSServer(cp, kp, http_ok_handler) as srv:
        found = asyncio.run(scan_subnet(
            "127.0.0.3", port=srv.port, timeout=1.0,
            network=ipaddress.ip_network("127.0.0.0/30")))
    assert [n.ip for n in found] == ["127.0.0.1"]
    assert found[0].tls_version == "TLSv1.3" and found[0].alpn == "h2"
    assert candidate_domains(found) == ["test.local", "www.test.local"]


def test_candidate_domains_filters_tls12_and_dupes():
    ns = [Neighbor("1.1.1.1", "TLSv1.2", "h2", ["old.example"]),
          Neighbor("1.1.1.2", "TLSv1.3", "h2", ["a.example", "b.example"]),
          Neighbor("1.1.1.3", "TLSv1.3", "", ["a.example"])]
    assert candidate_domains(ns) == ["a.example", "b.example"]
