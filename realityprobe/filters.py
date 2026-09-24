"""Фильтры доменов и валидация ввода."""

import ipaddress
import re

from .policy import is_excluded

# ── Input validation ───────────────────────────────────────────────────────
def sanitize_domain(d: str) -> str:
    d = d.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = re.sub(r'/.*$', '', d)
    d = re.sub(r':.*$', '', d)
    d = d.strip('.')
    if not d or not re.match(r'^[a-z0-9][a-z0-9\-\.]{2,253}$', d):
        return ""
    return d

def sanitize_ip(ip: str) -> str:
    """IP или хостнейм сервера для конфигов; мусор → плейсхолдер."""
    ip = ip.strip()
    if not ip: return "<SERVER_IP>"
    if parse_ip(ip): return ip
    if re.match(r'^[\d.]+$', ip): return "<SERVER_IP>"   # похоже на IPv4, но невалидно
    if re.match(r'^[a-z0-9][a-z0-9\-\.]{2,253}$', ip, re.I) and '.' in ip: return ip
    return "<SERVER_IP>"


def parse_ip(ip: str) -> str:
    """Нормализованный IP-литерал или "" — для ASN/подсетевых проверок."""
    try:
        return str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return ""


# ── Domains to NEVER scan (internal infrastructure) ────
# akadns.net, edgecastcdn.net, hwcdn.net — internal CDN resolvers without public TLS
# wip/activate/ereg — internal Adobe endpoints
# hinet.net, cdn20.com — regional CDN, not useful
# akamaihdwinsights.net, edgekey.net, akamaiedge.net — Akamai DNS balancers
INFRA_SUFFIXES = [
    ".akadns.net", ".edgecastcdn.net", ".hwcdn.net", ".hinet.net",
    ".cdn20.com", ".akamaiedge.net", ".edgekey.net", ".akamaihdwinsights.net",
    # akamaihd.net handled separately with whitelist
    ".trafficmanager.net",  # Azure traffic manager — no public TLS
    ".thron.com",           # B2B CDN
    ".msecnd.net",          # deprecated Microsoft CDN
]

INFRA_PREFIXES = [
    # Adobe internal/staging
    "activate.", "activate-", "ereg.", "wip.", "wip1.", "wip2.", "wip3.", "wip4.",
    "practivate.", "hlrcv.", "hlkb.", "lmlicenses.",
    "adobe-dns-", "3dns-",
    # Akamai internal
    "a4e", "a248.", "e122", "e9191", "a1887",
    # Apple DNS balancers
    "apple.com.akadns.", "push-apple.com.akadns.",
    "time.asia.", "time.euro.", "time.apple.",
]

def is_infra_domain(domain: str) -> bool:
    """Filters internal CDN infrastructure — not suitable for Reality SNI."""
    d = domain.lower()
    # suffixes
    for suf in INFRA_SUFFIXES:
        if d.endswith(suf): return True
    # akamaihd.net: allow only Steam, rest is internal infrastructure
    if d.endswith(".akamaihd.net"):
        AKAMAIHD_ALLOWED = {"steamcdn-a.akamaihd.net", "steamcommunity.akamaihd.net",
                            "cdn.akamai.steamstatic.com"}
        return d not in AKAMAIHD_ALLOWED
    # edgecastcdn.net — always infrastructure
    if "edgecastcdn" in d or "hwcdn" in d: return True
    # numeric hash-subdomains like "a4e8s8k3.map2.ssl.hwcdn.net"
    parts = d.split(".")
    if len(parts) >= 2:
        first = parts[0]
        if len(first) <= 10 and re.match(r'^[a-f0-9]{6,}$', first): return True
    # Adobe staging / wip
    for prefix in INFRA_PREFIXES:
        if d.startswith(prefix): return True
    # domains with numeric hash prefix: "e122475.dscg.akamaiedge.net"
    if re.match(r'^[a-z]\d{5,}\.', d): return True
    return False

def is_suitable_for_scan(domain: str) -> bool:
    """
    Final filter before scanning.
    True = domain is worth scanning as Reality SNI candidate.
    """
    if is_excluded(domain):   return False
    if is_infra_domain(domain):  return False
    d = domain.lower()
    # too short or missing dot
    if len(d) < 5 or '.' not in d: return False
    # valid characters only
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]{3,253}$', d): return False
    # IPv4 addresses — skip
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', d): return False
    # too many dots (deep subdomains like a.b.c.d.e.f.com)
    if d.count('.') > 4: return False
    return True

def looks_like_cdn(domain: str) -> bool:
    """Heuristic: domain looks like CDN/public infrastructure — suitable for Reality."""
    d = domain.lower()
    if not is_suitable_for_scan(d): return False
    # Exclude consumer-facing subdomains
    consumer_prefixes = [
        "mail.", "webmail.", "login.", "auth.", "account.", "accounts.",
        "shop.", "store.", "news.", "forum.", "wap.", "m.",
        "ads.", "ad.", "tracker.",
        "search.", "maps.", "translate.",
        "chat.", "meet.", "conference.",
    ]
    for kw in consumer_prefixes:
        if d.startswith(kw): return False
    # Positive CDN indicators
    cdn_kw = [
        "cdn", "static", "assets", "dl", "download", "delivery",
        "media", "storage", "content", "dist", "files",
        "update", "updates", "pkg", "release", "releases",
        "edge", "akamai", "fastly", "cloudflare",
        "gstatic", "googleapis", "githubusercontent",
        "azureedge", "msecnd",
        "apple.com", "microsoft.com", "google.com", "oracle.com",
        "adobe.com", "ibm.com", "salesforce.com", "github",
        "twitch", "dropbox", "cloudflare", "fastly",
        "jsdelivr", "unpkg", "cdnjs", "nuget", "npmjs",
        "jetbrains", "steam", "mozilla", "wikimedia",
        "bitwarden", "figma", "notion", "vercel", "netlify",
    ]
    return any(kw in d for kw in cdn_kw)
