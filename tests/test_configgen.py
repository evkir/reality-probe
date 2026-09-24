import urllib.parse as up

import pytest

from realityprobe import configgen


def test_tcp_vision_defaults():
    c = configgen.build("www.example.org", 443, "95.216.1.1")
    rs = c["xray_inbound"]["inbounds"][0]["streamSettings"]["realitySettings"]
    assert rs["target"] == "www.example.org:443"
    assert rs["serverNames"] == ["www.example.org"]
    assert "fingerprint" not in rs and "dest" not in rs
    assert "" not in rs["shortIds"] and all(len(s) % 2 == 0 and len(s) <= 16 for s in rs["shortIds"])
    out = c["xray_outbound"]["outbounds"][0]
    assert out["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"
    assert out["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert out["mux"]["enabled"] is False
    assert c["singbox_outbound"]["outbounds"][0]["tls"]["utls"]["fingerprint"] == "firefox"
    assert "client-fingerprint: firefox" in c["mihomo"]
    assert len(c["public_key"]) == 43 and len(c["private_key"]) == 43


def test_xhttp_has_no_flow_and_path():
    c = configgen.build("www.example.org", 443, "95.216.1.1", transport="xhttp", fingerprint="safari")
    inb = c["xray_inbound"]["inbounds"][0]
    assert "flow" not in inb["settings"]["clients"][0]
    ss = inb["streamSettings"]
    assert ss["network"] == "xhttp" and ss["xhttpSettings"]["extra"]["xPaddingBytes"] == "100-1000"
    assert c["xhttp_path"].startswith("/") and ss["xhttpSettings"]["path"] == c["xhttp_path"]
    assert "_unsupported" in c["singbox_inbound"]
    q = dict(up.parse_qsl(up.urlsplit(c["share_uri"]).query))
    assert q["type"] == "xhttp" and q["fp"] == "safari" and "flow" not in q
    assert q["path"] == c["xhttp_path"]


def test_share_uri_tcp():
    c = configgen.build("a.example", 8443, "1.2.3.4")
    u = up.urlsplit(c["share_uri"])
    assert u.hostname == "1.2.3.4" and u.port == 443
    q = dict(up.parse_qsl(u.query))
    assert q["flow"] == "xtls-rprx-vision" and q["sni"] == "a.example" and q["sid"] == c["short_ids"][0]
    assert c["xray_inbound"]["inbounds"][0]["streamSettings"]["realitySettings"]["target"] == "a.example:8443"


def test_validation():
    with pytest.raises(ValueError):
        configgen.build("a.example", 443, "1.2.3.4", transport="grpc")
    with pytest.raises(ValueError):
        configgen.build("a.example", 443, "1.2.3.4", fingerprint="evil")
