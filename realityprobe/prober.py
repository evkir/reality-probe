"""TLS-пробер target-а для Reality (v4)."""

import asyncio
import hashlib
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import urlsplit

from . import policy
from .certs import is_mitm_issuer, name_matches, parse_der
from .filters import is_infra_domain, is_suitable_for_scan, looks_like_cdn
from .netinfo import ASNResolver, IPInfo, resolver as default_resolver, same_prefix
from .scoring import PROFILE_STANDARD, Signals, evaluate, status_for
from .tlshello import kex_report

RISK_TO_QUALITY = {"low": "ideal", "medium": "good", "high": "poor"}


@dataclass
class ServerContext:
    """VPS, на котором будет Reality. Нужен для топологической оценки."""
    ip: str = ""
    info: Optional[IPInfo] = None

    @property
    def known(self) -> bool:
        return bool(self.ip)


@dataclass
class ProbeResult:
    domain:           str
    port:             int   = 443
    resolved_ip:      str   = ""
    all_ips:          list  = field(default_factory=list)
    ip_count:         int   = 0
    is_cdn:           bool  = False
    tls_version:      str   = ""
    tls_cipher:       str   = ""
    key_exchange:     str   = ""        # группа, выбранная на браузерный ClientHello
    mlkem:            Optional[bool] = None
    alpn_negotiated:  str   = ""
    h2_supported:     bool  = False
    cert_subject:     str   = ""
    cert_issuer:      str   = ""
    cert_fp_sha256:   str   = ""
    cert_valid:       bool  = False     # сертификат покрывает SNI
    cert_tampered:    bool  = False
    cert_days_left:   int   = 0
    http_status:      int   = 0
    http_redirect:    bool  = False
    redirect_location: str  = ""
    redirect_offsite: bool  = False
    donor_asn:        Optional[int] = None
    donor_prefix:     str   = ""
    donor_holder:     str   = ""
    donor_cloudflare: bool  = False
    topology:         str   = "unknown"
    overused:         bool  = False
    ru_whitelisted:   bool  = False
    rtt_ms:           list  = field(default_factory=list)
    rtt_avg:          float = 0.0
    rtt_jitter:       float = 0.0
    connection_reset: bool  = False
    timeout:          bool  = False
    blocked_rkn:      bool  = False     # исключён (недоступен в РФ)
    tcp_unreachable:  bool  = False
    error:            str   = ""
    score:            float = 0.0
    tspu_risk:        str   = "high"
    notes:            list  = field(default_factory=list)
    dpi_quality:      str   = ""        # совместимость с v3-экспортом
    suitable:         bool  = False
    status:           str   = ""


def _classify_conn_error(e: BaseException) -> str:
    if isinstance(e, asyncio.TimeoutError):
        return "timeout"
    es = str(e).lower()
    if isinstance(e, ConnectionResetError) or "reset" in es:
        return "rst"
    if isinstance(e, ConnectionRefusedError) or "refused" in es:
        return "refused"
    return "error"


def _redirect_offsite(domain: str, location: str) -> bool:
    if not location:
        return False
    host = (urlsplit(location).hostname or "").lower()
    return bool(host) and host != domain.lower()


class TLSProber:
    TLS_TIMEOUT = 4.5
    PROBE_COUNT = 2

    def __init__(self, port: int = 443, server: Optional[ServerContext] = None,
                 profile: str = PROFILE_STANDARD, asn: Optional[ASNResolver] = None,
                 stop: Callable[[], bool] = lambda: False):
        self.port = port
        self.server = server or ServerContext()
        self.profile = profile
        self.asn = asn or default_resolver
        self.stop = stop

    @staticmethod
    def _ctx(alpn: List[str]) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        ctx.set_alpn_protocols(alpn)
        return ctx

    async def _resolve(self, domain: str) -> List[str]:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                domain, self.port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
            timeout=3.5)
        ips = list(dict.fromkeys(i[4][0] for i in infos))
        # IPv4 первым: VPS почти всегда задан IPv4, и ТСПУ работает по нему
        return sorted(ips, key=lambda ip: ":" in ip)

    async def _handshakes(self, r: ProbeResult) -> None:
        ctx = self._ctx(["h2", "http/1.1"])
        for attempt in range(self.PROBE_COUNT):
            if self.stop():
                break
            t0 = time.perf_counter()
            writer = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(r.resolved_ip, self.port, ssl=ctx,
                                            server_hostname=r.domain,
                                            ssl_handshake_timeout=self.TLS_TIMEOUT),
                    timeout=self.TLS_TIMEOUT + 0.5)
                r.rtt_ms.append(round((time.perf_counter() - t0) * 1000, 1))
                if attempt == 0:
                    self._read_session(r, writer.get_extra_info("ssl_object"))
            except Exception as e:
                kind = _classify_conn_error(e)
                if kind == "timeout":
                    r.timeout = True
                elif kind == "rst":
                    r.connection_reset = True
                elif kind == "refused":
                    r.tcp_unreachable = True
                    r.error = "TCP refused — порт закрыт"
                else:
                    r.error = str(e)[:120]
                break
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), 0.5)
                    except Exception:
                        pass
            if attempt < self.PROBE_COUNT - 1:
                await asyncio.sleep(0.15)

    @staticmethod
    def _read_session(r: ProbeResult, sock) -> None:
        if not sock:
            return
        r.tls_version = sock.version() or ""
        cipher = sock.cipher()
        r.tls_cipher = cipher[0] if cipher else ""
        r.alpn_negotiated = sock.selected_alpn_protocol() or ""
        r.h2_supported = r.alpn_negotiated == "h2"
        der = sock.getpeercert(binary_form=True)
        if not der:
            return
        r.cert_fp_sha256 = hashlib.sha256(der).hexdigest()
        try:
            ci = parse_der(der)
        except Exception:
            return
        r.cert_subject = ci.subject_cn
        r.cert_issuer = ci.issuer_org or ci.issuer_cn
        r.cert_days_left = ci.days_left
        r.cert_valid = name_matches(r.domain, ci.names)
        r.cert_tampered = is_mitm_issuer(ci)

    async def _http_status(self, r: ProbeResult) -> None:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(r.resolved_ip, self.port,
                                        ssl=self._ctx(["http/1.1"]),
                                        server_hostname=r.domain,
                                        ssl_handshake_timeout=3.0),
                timeout=4.0)
            writer.write((f"GET / HTTP/1.1\r\nHost: {r.domain}\r\n"
                          "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) "
                          "Gecko/20100101 Firefox/140.0\r\n"
                          "Accept: text/html\r\nConnection: close\r\n\r\n").encode())
            await writer.drain()
            head = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        except Exception:
            return
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 0.5)
                except Exception:
                    pass
        lines = head.decode("latin-1", errors="ignore").split("\r\n")
        parts = lines[0].split(" ") if lines else []
        if len(parts) >= 2 and parts[1].isdigit():
            r.http_status = int(parts[1])
        if 300 <= r.http_status < 400:
            r.http_redirect = True
            for line in lines[1:]:
                if line.lower().startswith("location:"):
                    r.redirect_location = line.split(":", 1)[1].strip()
                    break
            r.redirect_offsite = _redirect_offsite(r.domain, r.redirect_location)

    async def _donor_asn(self, r: ProbeResult) -> None:
        info = await asyncio.get_running_loop().run_in_executor(
            None, self.asn.lookup, r.resolved_ip)
        r.donor_asn, r.donor_prefix, r.donor_holder = info.asn, info.prefix, info.holder
        if not self.server.known:
            return
        srv = self.server.info or IPInfo(ip=self.server.ip)
        if same_prefix(srv, info):
            r.topology = "same_prefix"
        elif srv.asn and info.asn:
            r.topology = "same_asn" if srv.asn == info.asn else "foreign"

    async def _kex(self, r: ProbeResult) -> None:
        rep = await kex_report(r.resolved_ip, self.port, r.domain, timeout=self.TLS_TIMEOUT)
        if not rep.error:
            r.key_exchange, r.mlkem = rep.preferred, rep.mlkem

    async def probe(self, domain: str) -> ProbeResult:
        r = ProbeResult(domain=domain, port=self.port)
        r.overused = policy.is_overused(domain)
        r.ru_whitelisted = policy.is_ru_whitelisted(domain)

        if policy.is_excluded(domain):
            r.blocked_rkn, r.status, r.error = True, "blocked", "Недоступен в РФ — исключён"
            return r
        if is_infra_domain(domain) or not is_suitable_for_scan(domain):
            r.status, r.error = "skipped", "Служебная CDN-инфраструктура — не SNI"
            return r

        try:
            r.all_ips = await self._resolve(domain)
        except asyncio.TimeoutError:
            r.status, r.error, r.timeout = "timeout", "DNS timeout", True
            return r
        except Exception as e:
            r.status, r.error = "error", f"DNS: {e}"[:120]
            return r
        if not r.all_ips:
            r.status, r.error = "error", "DNS: нет адресов"
            return r
        r.resolved_ip, r.ip_count = r.all_ips[0], len(r.all_ips)
        r.is_cdn = r.ip_count > 1 or looks_like_cdn(domain)
        r.donor_cloudflare = policy.is_cloudflare_ip(r.resolved_ip)

        await self._handshakes(r)
        if r.rtt_ms:
            r.rtt_avg = round(sum(r.rtt_ms) / len(r.rtt_ms), 1)
            r.rtt_jitter = round(max(r.rtt_ms) - min(r.rtt_ms), 1)

        if r.tls_version and not self.stop():
            await asyncio.gather(self._http_status(r), self._donor_asn(r), self._kex(r),
                                 return_exceptions=True)

        self._finalize(r)
        return r

    def _finalize(self, r: ProbeResult) -> None:
        fatal = r.timeout or r.connection_reset or r.cert_tampered or not r.tls_version
        brand = policy.big_brand(r.donor_asn)
        v = evaluate(Signals(
            tls_version=r.tls_version, h2=r.h2_supported, mlkem=r.mlkem,
            preferred_group=r.key_exchange,
            cert_matches=r.cert_valid if r.cert_fp_sha256 else None,
            http_status=r.http_status,
            redirect_offsite=r.redirect_offsite,
            redirect_onsite=r.http_redirect and not r.redirect_offsite,
            rtt_avg=r.rtt_avg, topology=r.topology,
            donor_brand=brand, donor_cloudflare=r.donor_cloudflare,
            server_known=self.server.known, overused=r.overused,
            ru_whitelisted=r.ru_whitelisted, profile=self.profile, fatal=fatal))
        r.score, r.tspu_risk, r.suitable, r.notes = v.score, v.risk, v.suitable, v.notes
        r.dpi_quality = RISK_TO_QUALITY[r.tspu_risk]

        if r.cert_tampered:
            r.status = "tampered"
        elif r.connection_reset:
            r.status = "rst"
        elif r.timeout:
            r.status = "timeout"
        elif r.error or not r.tls_version:
            r.status = "error"
            r.error = r.error or "TLS не установлен"
        elif r.redirect_offsite:
            r.status = "redirect"
        else:
            r.status = status_for(r.score) if r.suitable else "poor"
