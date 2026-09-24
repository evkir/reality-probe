"""
Поиск доноров в подсети VPS (идея XTLS/RealiTLScanner).

Лучший target 2026 — реальный сайт в той же /24, что и сервер: для ТСПУ
связка SNI ↔ IP выглядит естественно. Подключаемся к каждому хосту без SNI,
читаем сертификат и берём из него конкретные имена как кандидатов в SNI.
"""

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass, field, asdict
from typing import Callable, List, Optional

from .certs import concrete_names, parse_der
from .policy import is_excluded

MAX_HOSTS = 1024


@dataclass
class Neighbor:
    ip: str
    tls_version: str = ""
    alpn: str = ""
    names: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def neighbor_network(server_ip: str, prefix_len: int = 24) -> ipaddress.IPv4Network:
    addr = ipaddress.ip_address(server_ip)
    if addr.version != 4:
        raise ValueError("сканирование подсети поддерживается только для IPv4")
    if not 20 <= prefix_len <= 30:
        raise ValueError("размер подсети: /20…/30")
    return ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)


async def _probe_host(ip: str, port: int, timeout: float) -> Optional[Neighbor]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=None,
                                    ssl_handshake_timeout=timeout),
            timeout + 0.5)
        sock = writer.get_extra_info("ssl_object")
        n = Neighbor(ip=ip, tls_version=sock.version() or "",
                     alpn=sock.selected_alpn_protocol() or "")
        der = sock.getpeercert(binary_form=True)
        if der:
            try:
                n.names = [d for d in concrete_names(parse_der(der).names) if not is_excluded(d)]
            except Exception:
                pass
        return n
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.5)
            except Exception:
                pass


async def scan_subnet(server_ip: str, port: int = 443, prefix_len: int = 24,
                      concurrency: int = 64, timeout: float = 2.5,
                      network: Optional[ipaddress.IPv4Network] = None,
                      stop: Callable[[], bool] = lambda: False,
                      on_progress: Callable[[int, int], None] = lambda done, total: None
                      ) -> List[Neighbor]:
    net = network or neighbor_network(server_ip, prefix_len)
    hosts = [str(h) for h in net.hosts() if str(h) != server_ip][:MAX_HOSTS]
    sem = asyncio.Semaphore(concurrency)
    found: List[Neighbor] = []
    done = 0

    async def one(ip):
        nonlocal done
        if stop():
            return
        async with sem:
            n = await _probe_host(ip, port, timeout)
        done += 1
        on_progress(done, len(hosts))
        if n and n.tls_version:
            found.append(n)

    await asyncio.gather(*(one(h) for h in hosts))
    found.sort(key=lambda n: (n.tls_version != "TLSv1.3", n.alpn != "h2", n.ip))
    return found


def candidate_domains(neighbors: List[Neighbor]) -> List[str]:
    """Кандидаты для полного пробинга: только TLS 1.3, h2 — в начале."""
    seen, out = set(), []
    for n in neighbors:
        if n.tls_version != "TLSv1.3":
            continue
        for d in n.names:
            if d not in seen:
                seen.add(d)
                out.append(d)
    return out
