"""
Модель политик ТСПУ (РФ) по состоянию на лето 2026.

Что изменилось относительно 2024–2025 и на чём построен v4:

1. Заморозка ~15–20 КБ / ~25 пакетов сервер→клиент на TCP к зарубежным
   IP из дата-центровых ASN (Hetzner, DO, Vultr, OVH…). Протокол не важен —
   решает связка «подозрительная подсеть + fingerprint + частота к SNI».
2. Проверка согласованности SNI ↔ IP: SNI крупного бренда (Apple, Microsoft,
   Google, Cloudflare…) на IP хостера — аномалия. Лучший target — сайт
   в той же подсети / ASN, что и сервер (подход RealiTLScanner).
3. «Затёртые» SNI (microsoft.com, apple.com, lovelive-anime.jp…) — в
   эвристиках в первую очередь.
4. Fingerprint `chrome` (uTLS Chrome 13x) — под подозрением; стабильнее
   firefox/safari. Быстрая смена fp под нагрузкой → бан узла ~600 с.
5. Режим белых списков (мобильные сети, регионы): TLS проходит только
   с SNI из списка одобренных российских ресурсов.
6. Современные браузеры шлют X25519MLKEM768 — target должен его
   поддерживать, чтобы ответ при active probing совпадал с реальным.
"""

import ipaddress
from typing import Optional

# ── Недоступные / замедленные в РФ ресурсы — как target бесполезны ─────────
EXCLUDED_DOMAINS = {
    "www.linkedin.com", "linkedin.com",
    "www.facebook.com", "facebook.com", "instagram.com", "www.instagram.com",
    "whatsapp.com", "www.whatsapp.com",
    "twitter.com", "x.com", "t.co",
    "discord.com", "gateway.discord.gg", "cdn.discordapp.com",
    "signal.org", "www.signal.org",
    "www.youtube.com", "youtube.com",
    "soundcloud.com",
    "telegram.org", "web.telegram.org",
    "www.roblox.com", "roblox.com",
    "www.viber.com",
}

EXCLUDED_KEYWORDS = [
    "facebook", "instagram", "fbcdn", "whatsapp",
    "twitter", "twimg", "linkedin", "licdn",
    "discord", "signal.org",
    "youtube", "googlevideo", "ytimg",
    "soundcloud", "roblox", "viber",
    "telegram.org",
    "tiktok", "bytedance",
    "amazonaws", "cloudfront.net",
]

# ── «Затёртые» SNI — встречаются в тысячах гайдов, ТСПУ их знает ────────────
OVERUSED_SNI = {
    "www.microsoft.com", "microsoft.com", "update.microsoft.com",
    "www.bing.com", "login.microsoftonline.com",
    "www.apple.com", "apple.com", "swdist.apple.com", "itunes.apple.com",
    "www.icloud.com", "icloud.com", "gateway.icloud.com",
    "www.google.com", "google.com", "dl.google.com", "www.gstatic.com",
    "www.cloudflare.com", "cloudflare.com", "speed.cloudflare.com",
    "www.lovelive-anime.jp",
    "www.yahoo.com", "yahoo.com",
    "www.samsung.com", "www.amazon.com", "amazon.com",
    "addons.mozilla.org", "www.mozilla.org",
    "www.speedtest.net", "github.com", "www.github.com",
    "www.nvidia.com", "www.tesla.com", "www.cisco.com",
    "www.asus.com", "www.twitch.tv", "www.visa.com",
    "www.dropbox.com", "www.oracle.com",
}

# ── Белый список SNI (режим «белых списков» на мобильных сетях) ────────────
# Публично наблюдаемое ядро списка. Полный список не публикуется и
# отличается по регионам — это ориентир, а не гарантия.
RU_WHITELIST_SUFFIXES = [
    "yandex.ru", "ya.ru", "yandex.net", "yastatic.net", "dzen.ru",
    "kinopoisk.ru", "vk.com", "vk.ru", "userapi.com", "vkvideo.ru",
    "mail.ru", "ok.ru", "max.ru", "rutube.ru",
    "gosuslugi.ru", "mos.ru", "nalog.gov.ru", "gov.ru",
    "ozon.ru", "wildberries.ru", "wb.ru", "avito.ru", "market.yandex.ru",
    "sberbank.ru", "sber.ru", "tbank.ru", "vtb.ru", "alfabank.ru",
    "gazprombank.ru", "pochta.ru", "rzd.ru", "2gis.ru", "hh.ru",
    "mts.ru", "megafon.ru", "beeline.ru", "t2.ru", "rt.ru",
    "kaspersky.ru", "1c.ru",
]

# ── ASN крупных брендов/CDN: SNI из их зоны на IP хостера = аномалия ───────
BIG_BRAND_ASNS = {
    13335: "Cloudflare", 209242: "Cloudflare",
    20940: "Akamai", 16625: "Akamai", 21342: "Akamai", 33905: "Akamai",
    54113: "Fastly",
    15169: "Google", 36040: "Google/YouTube",
    8075: "Microsoft", 8068: "Microsoft", 8069: "Microsoft",
    714: "Apple", 6185: "Apple",
    16509: "Amazon", 14618: "Amazon",
    32934: "Meta",
    2906: "Netflix",
    13414: "Twitter",
}

# ── Дата-центровые ASN, по которым ТСПУ массово включает заморозку ─────────
DATACENTER_ASNS = {
    24940: "Hetzner", 213230: "Hetzner Cloud",
    14061: "DigitalOcean",
    20473: "Vultr/Choopa",
    16276: "OVH",
    63949: "Akamai/Linode",
    51167: "Contabo", 40021: "Contabo US",
    12876: "Scaleway",
    210644: "Aeza",
    47583: "Hostinger",
    9009: "M247",
    60781: "Leaseweb NL", 28753: "Leaseweb DE",
    396982: "Google Cloud",
    31898: "Oracle Cloud",
    45102: "Alibaba Cloud",
    132203: "Tencent Cloud",
    8560: "IONOS",
    197540: "netcup",
    53667: "FranTech/BuyVM",
    36007: "Kamatera",
    202053: "UpCloud",
    199524: "G-Core",
    44477: "Stark Industries",
    62240: "Clouvider",
}

# ── Официальные IPv4-диапазоны Cloudflare (cloudflare.com/ips-v4) ──────────
CLOUDFLARE_V4 = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)]
CLOUDFLARE_V6 = [ipaddress.ip_network(n) for n in (
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)]

# ── Fingerprint: порядок перебора для клиента (лето 2026) ──────────────────
FINGERPRINTS_RECOMMENDED = ["firefox", "safari", "qq", "edge", "chrome", "randomized"]
FINGERPRINT_DEFAULT = "firefox"

# Порог заморозки: сервер→клиент
FREEZE_MIN_BYTES = 12 * 1024
FREEZE_MAX_BYTES = 24 * 1024


def _norm(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _matches_suffix(d: str, suffix: str) -> bool:
    return d == suffix or d.endswith("." + suffix)


def is_excluded(domain: str) -> bool:
    d = _norm(domain)
    if d in EXCLUDED_DOMAINS:
        return True
    return any(kw in d for kw in EXCLUDED_KEYWORDS)


def is_overused(domain: str) -> bool:
    return _norm(domain) in OVERUSED_SNI


def is_ru_whitelisted(domain: str) -> bool:
    d = _norm(domain)
    return any(_matches_suffix(d, s) for s in RU_WHITELIST_SUFFIXES)


def is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = CLOUDFLARE_V4 if addr.version == 4 else CLOUDFLARE_V6
    return any(addr in n for n in nets)


def big_brand(asn: Optional[int]) -> Optional[str]:
    return BIG_BRAND_ASNS.get(asn) if asn else None


def datacenter(asn: Optional[int]) -> Optional[str]:
    return DATACENTER_ASNS.get(asn) if asn else None
