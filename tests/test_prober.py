import asyncio
import functools

from realityprobe.netinfo import ASNResolver, IPInfo
from realityprobe.prober import ServerContext, TLSProber, _redirect_offsite
from conftest import TLSServer, http_ok_handler


def _asn(asn=24940, prefix="127.0.0.0/8"):
    def fetch(url):
        if "network-info" in url:
            return {"data": {"asns": [str(asn)], "prefix": prefix}}
        return {"data": {"holder": "TEST-AS"}}
    return ASNResolver(fetch=fetch)


class LocalProber(TLSProber):
    async def _resolve(self, domain):
        return ["127.0.0.1"]


def _run(port, handler_srv_port, server=None, domain="test.local", asn=None):
    p = LocalProber(port=handler_srv_port, server=server, asn=asn or _asn())
    return asyncio.run(p.probe(domain))


def test_probe_same_prefix_local(cert_files):
    _, cp, kp = cert_files
    srv_ctx = ServerContext(ip="127.0.0.5", info=IPInfo("127.0.0.5", 24940, "127.0.0.0/8"))
    with TLSServer(cp, kp, http_ok_handler) as srv:
        r = _run(443, srv.port, server=srv_ctx)
    assert r.tls_version == "TLSv1.3" and r.h2_supported
    assert r.cert_valid and r.cert_subject == "test.local" and r.cert_issuer == "Test Org"
    assert r.http_status == 200 and not r.http_redirect
    assert r.topology == "same_prefix"
    assert r.key_exchange in ("X25519", "X25519MLKEM768")
    assert r.suitable and r.tspu_risk in ("low", "medium")
    assert r.status in ("ideal", "excellent")


def test_probe_offsite_redirect(cert_files):
    _, cp, kp = cert_files
    handler = functools.partial(http_ok_handler, status=b"301 Moved Permanently",
                                extra=b"Location: https://other.example/\r\n")
    with TLSServer(cp, kp, handler) as srv:
        r = _run(443, srv.port)
    assert r.http_redirect and r.redirect_offsite
    assert r.status == "redirect" and not r.suitable


def test_probe_cert_mismatch_and_no_server(cert_files):
    _, cp, kp = cert_files
    with TLSServer(cp, kp, http_ok_handler) as srv:
        r = _run(443, srv.port, domain="other.example")
    assert not r.cert_valid and not r.suitable
    assert r.topology == "unknown"


def test_probe_refused_and_excluded():
    r = _run(443, 1)
    assert r.status == "error" and r.tcp_unreachable
    r = asyncio.run(LocalProber().probe("www.instagram.com"))
    assert r.status == "blocked"
    r = asyncio.run(LocalProber().probe("e122475.dscg.akamaiedge.net"))
    assert r.status == "skipped"


def test_redirect_offsite_helper():
    assert _redirect_offsite("a.com", "https://b.com/x")
    assert not _redirect_offsite("a.com", "/en/")
    assert not _redirect_offsite("a.com", "https://A.com/en/")
