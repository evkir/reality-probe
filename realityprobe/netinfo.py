"""
ASN / префикс IP-адреса — для проверки топологической согласованности
SNI ↔ IP (ТСПУ сравнивает SNI с тем, кому принадлежит IP).

Источник: RIPEstat (без ключа). Работает и без сети — тогда ASN неизвестен,
а скоринг опирается на офлайн-признаки (диапазоны Cloudflare и т.п.).
"""

import ipaddress
import json
import threading
import urllib.request
from dataclasses import dataclass, asdict
from typing import Callable, Dict, Optional

RIPE_NETINFO = "https://stat.ripe.net/data/network-info/data.json?resource={}"
RIPE_ASOVERVIEW = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{}"


@dataclass
class IPInfo:
    ip: str
    asn: Optional[int] = None
    prefix: str = ""
    holder: str = ""

    def to_dict(self):
        return asdict(self)


def _http_json(url: str, timeout: float = 6.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "reality-probe/4"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))


class ASNResolver:
    """Потокобезопасный кеш IP → ASN/префикс. fetch подменяется в тестах."""

    def __init__(self, fetch: Callable[[str], dict] = _http_json):
        self._fetch = fetch
        self._by_ip: Dict[str, IPInfo] = {}
        self._prefixes: Dict[str, IPInfo] = {}
        self._holders: Dict[int, str] = {}
        self._lock = threading.Lock()

    def _from_prefix_cache(self, ip: str) -> Optional[IPInfo]:
        addr = ipaddress.ip_address(ip)
        for pfx, info in self._prefixes.items():
            net = ipaddress.ip_network(pfx, strict=False)
            if addr.version == net.version and addr in net:
                return IPInfo(ip=ip, asn=info.asn, prefix=info.prefix, holder=info.holder)
        return None

    def lookup(self, ip: str) -> IPInfo:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return IPInfo(ip=ip)
        with self._lock:
            if ip in self._by_ip:
                return self._by_ip[ip]
            cached = self._from_prefix_cache(ip)
        if cached:
            with self._lock:
                self._by_ip[ip] = cached
            return cached

        info = IPInfo(ip=ip)
        try:
            data = self._fetch(RIPE_NETINFO.format(ip)).get("data", {})
            asns = data.get("asns") or []
            if asns:
                info.asn = int(asns[0])
            info.prefix = data.get("prefix") or ""
        except Exception:
            # офлайн — не кешируем неудачу, чтобы повторить позже
            return info
        if info.asn:
            info.holder = self._holder(info.asn)
        with self._lock:
            self._by_ip[ip] = info
            if info.prefix:
                self._prefixes[info.prefix] = info
        return info

    def _holder(self, asn: int) -> str:
        with self._lock:
            if asn in self._holders:
                return self._holders[asn]
        holder = ""
        try:
            holder = self._fetch(RIPE_ASOVERVIEW.format(asn)).get("data", {}).get("holder", "") or ""
        except Exception:
            pass
        with self._lock:
            self._holders[asn] = holder
        return holder


def same_prefix(a: IPInfo, b: IPInfo) -> bool:
    """Оба IP в одном анонсированном префиксе (или в одной /24 при отсутствии данных)."""
    try:
        ia, ib = ipaddress.ip_address(a.ip), ipaddress.ip_address(b.ip)
    except ValueError:
        return False
    if ia.version != ib.version:
        return False
    for info in (a, b):
        if info.prefix:
            net = ipaddress.ip_network(info.prefix, strict=False)
            if net.version == ia.version and ia in net and ib in net:
                return True
    bits = 24 if ia.version == 4 else 48
    return ipaddress.ip_network(f"{ia}/{bits}", strict=False) == \
        ipaddress.ip_network(f"{ib}/{bits}", strict=False)


resolver = ASNResolver()
