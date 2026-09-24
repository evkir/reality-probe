import ipaddress

import pytest

from realityprobe import runner
from conftest import TLSServer, http_ok_handler
from test_prober import LocalProber, _asn


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "HISTORY_FILE", str(tmp_path / "h.json"))
    monkeypatch.setattr(runner, "HISTORY_DIR", str(tmp_path))
    runner.probe_state["running"] = False
    yield
    runner.probe_state["running"] = False


def test_try_start_is_exclusive():
    assert runner.try_start("scan")
    assert not runner.try_start("scan")


def test_run_scan_local(cert_files):
    _, cp, kp = cert_files
    with TLSServer(cp, kp, http_ok_handler) as srv:
        assert runner.try_start("scan")
        runner.run_scan(["test.local", "www.test.local"], srv.port, 4,
                        server_ip="127.0.0.9", asn=_asn(), prober_cls=LocalProber,
                        pre_results=[{"domain": "x.com", "status": "blocked", "score": 0}])
    st = runner.probe_state
    assert not st["running"] and st["progress"] == st["total"] == 3
    assert st["server"]["asn"] == 24940 and st["server"]["datacenter"] == "Hetzner"
    ok = [r for r in st["results"] if r["domain"] == "test.local"][0]
    assert ok["topology"] == "same_prefix" and ok["suitable"]
    assert any("DC-ASN" in l for l in st["log"])
    assert runner.load_history()[-1]["server"] == "127.0.0.9"


def test_run_subnet_local(cert_files):
    _, cp, kp = cert_files
    with TLSServer(cp, kp, http_ok_handler) as srv:
        assert runner.try_start("subnet")
        runner.run_subnet("127.0.0.3", srv.port, 8, asn=_asn(), prober_cls=LocalProber,
                          network=ipaddress.ip_network("127.0.0.0/30"))
    st = runner.probe_state
    assert [n["ip"] for n in st["neighbors"]] == ["127.0.0.1"]
    assert {r["domain"] for r in st["results"]} == {"test.local", "www.test.local"}


def test_stop_cancels_quickly():
    import asyncio
    import time as _t

    class SlowProber(LocalProber):
        async def probe(self, domain):
            await asyncio.sleep(20)

    assert runner.try_start("scan")
    import threading
    t = threading.Thread(target=runner.run_scan,
                         kwargs=dict(domains=[f"d{i}.example" for i in range(5)], port=443,
                                     concurrency=2, asn=_asn(), prober_cls=SlowProber))
    t0 = _t.perf_counter()
    t.start()
    _t.sleep(0.3)
    runner.probe_state["stop_requested"] = True
    t.join(5)
    assert not t.is_alive() and _t.perf_counter() - t0 < 3
    assert not runner.probe_state["running"]
    assert any("Остановлено" in l for l in runner.probe_state["log"])
