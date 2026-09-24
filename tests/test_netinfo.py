from realityprobe.netinfo import ASNResolver, IPInfo, same_prefix


def _fake_fetch(calls):
    def fetch(url):
        calls.append(url)
        if "network-info" in url:
            return {"data": {"asns": ["24940"], "prefix": "95.216.0.0/16"}}
        return {"data": {"holder": "HETZNER-AS"}}
    return fetch


def test_lookup_and_prefix_cache():
    calls = []
    r = ASNResolver(fetch=_fake_fetch(calls))
    a = r.lookup("95.216.1.1")
    assert a.asn == 24940 and a.prefix == "95.216.0.0/16" and a.holder == "HETZNER-AS"
    b = r.lookup("95.216.200.3")           # из кеша префикса, без сети
    assert b.asn == 24940
    assert len(calls) == 2


def test_lookup_offline_not_cached():
    def boom(url):
        raise OSError("offline")
    r = ASNResolver(fetch=boom)
    assert r.lookup("1.1.1.1").asn is None
    assert r.lookup("not-an-ip").asn is None


def test_same_prefix():
    a = IPInfo("95.216.1.1", 24940, "95.216.0.0/16")
    b = IPInfo("95.216.9.9", 24940, "95.216.0.0/16")
    c = IPInfo("5.9.1.1", 24940, "5.9.0.0/16")
    assert same_prefix(a, b)
    assert not same_prefix(a, c)
    assert same_prefix(IPInfo("10.0.0.1"), IPInfo("10.0.0.200"))   # /24 fallback
    assert not same_prefix(IPInfo("10.0.0.1"), IPInfo("::1"))
