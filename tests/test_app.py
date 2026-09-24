import time

import pytest

from realityprobe import app as appmod, runner


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "HISTORY_FILE", str(tmp_path / "h.json"))
    monkeypatch.setattr(runner, "HISTORY_DIR", str(tmp_path))
    appmod._rate.clear()
    runner.probe_state["running"] = False
    return appmod.app.test_client()


def test_index_served_and_escaped_helpers(client):
    r = client.get("/")
    body = r.get_data(as_text=True)
    assert r.status_code == 200 and "Reality Probe" in body and "const esc=" in body
    assert "onclick=\"genConfig('${" not in body          # домены не вставляются в JS-строки
    assert r.headers["X-Frame-Options"] == "DENY"


def test_genconfig_validation(client):
    assert client.post("/api/genconfig", json={"domain": "bad domain"}).status_code == 400
    assert client.post("/api/genconfig", json={"domain": "a.example", "transport": "grpc"}).status_code == 400
    d = client.post("/api/genconfig", json={"domain": "a.example", "server_ip": "1.2.3.4",
                                            "transport": "xhttp", "fingerprint": "safari"}).get_json()
    assert d["transport"] == "xhttp" and d["fingerprint"] == "safari" and d["xray"]


def test_probe_rejects_bad_server_ip(client):
    r = client.post("/api/probe", json={"domains": "a.example", "server_ip": "not-an-ip"})
    assert r.status_code == 400


def test_probe_prefilters_and_runs(client, monkeypatch):
    calls = {}

    def fake_run_scan(domains, port, conc, profile, server_ip, pre_results):
        calls.update(domains=domains, pre=[p["status"] for p in pre_results],
                     profile=profile, server_ip=server_ip, conc=conc)
        runner.probe_state["running"] = False
    monkeypatch.setattr(runner, "run_scan", fake_run_scan)
    r = client.post("/api/probe", json={
        "domains": "www.instagram.com\nhttps://Good.Example/path\n# c\ngood.example\ne122475.dscg.akamaiedge.net",
        "server_ip": " 95.216.1.1 ", "profile": "whitelist", "concurrency": 999})
    assert r.status_code == 200
    for _ in range(50):
        if calls:
            break
        time.sleep(0.02)
    assert calls["domains"] == ["good.example"]
    assert sorted(calls["pre"]) == ["blocked", "skipped"]
    assert calls["profile"] == "whitelist" and calls["server_ip"] == "95.216.1.1" and calls["conc"] == 40


def test_busy_runner(client):
    assert runner.try_start("scan")
    r = client.post("/api/probe", json={"domains": "a.example"})
    assert r.status_code == 400
    r = client.post("/api/subnet", json={"server_ip": "1.2.3.4"})
    assert r.status_code == 400


def test_subnet_validation(client):
    assert client.post("/api/subnet", json={}).status_code == 400
    assert client.post("/api/subnet", json={"server_ip": "2a01::1"}).status_code == 400


def test_defaults_profiles(client):
    wl = client.get("/api/defaults?profile=whitelist").get_json()
    assert "ya.ru" in wl["domains"].split("\n")
    std = client.get("/api/defaults").get_json()
    assert "www.microsoft.com" not in std["domains"].split("\n")


def test_freeze_validation(client):
    assert client.post("/api/freeze", json={"sni": ""}).status_code == 400
    assert client.post("/api/freeze", json={"sni": "a.example", "target_ip": "x"}).status_code == 400
    assert client.post("/api/freeze", json={"sni": "a.example", "target_ip": "1.2.3.4",
                                            "path": "/a b"}).status_code == 400


def test_export(client):
    assert client.get("/api/export/csv").status_code == 404
    runner.probe_state["results"] = [{"domain": "a.example", "score": 90, "suitable": True,
                                      "tspu_risk": "low", "notes": ["x", "y"], "status": "ideal"}]
    r = client.get("/api/export/csv")
    assert r.status_code == 200 and "x; y" in r.get_data(as_text=True)
    assert client.get("/api/export/zip").status_code == 200
    assert client.get("/api/export/json").get_json()["total"] == 1
    assert client.get("/api/export/xml").status_code == 404
    runner.probe_state["results"] = []


def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(runner, "run_scan", lambda *a, **k: runner.probe_state.update(running=False))
    codes = []
    for _ in range(appmod.RATE_PROBE + 1):
        runner.probe_state["running"] = False
        codes.append(client.post("/api/probe", json={"domains": "a.example"}).status_code)
    assert codes[-1] == 429
