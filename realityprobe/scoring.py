"""
Скоринг target-а для Reality под политики ТСПУ 2026.

Главный сдвиг относительно v3: решает не «красота» TLS-профиля донора
(TLS1.3+H2 есть почти у всех), а правдоподобие связки SNI ↔ IP сервера.
Поэтому топология (тот же префикс / ASN, что у VPS) весит больше всего,
а «затёртые» SNI и SNI крупных брендов на IP хостера штрафуются.

Без IP сервера максимум ~70 баллов (EXCELLENT): оценить главный риск
нельзя, и инструмент честно это показывает.
"""

from dataclasses import dataclass, field
from typing import List, Optional

PROFILE_STANDARD = "standard"
PROFILE_WHITELIST = "whitelist"


@dataclass
class Signals:
    tls_version: str = ""
    h2: bool = False
    mlkem: Optional[bool] = None
    preferred_group: str = ""
    cert_matches: Optional[bool] = None
    http_status: int = 0
    redirect_offsite: bool = False
    redirect_onsite: bool = False
    rtt_avg: float = 0.0
    topology: str = "unknown"          # same_prefix / same_asn / foreign / unknown
    donor_brand: Optional[str] = None  # имя из BIG_BRAND_ASNS
    donor_cloudflare: bool = False
    server_known: bool = False
    overused: bool = False
    ru_whitelisted: bool = False
    profile: str = PROFILE_STANDARD
    fatal: bool = False                # timeout / RST / MITM / нет TLS


@dataclass
class Verdict:
    score: float = 0.0
    risk: str = "high"                 # low / medium / high
    suitable: bool = False
    notes: List[str] = field(default_factory=list)


def evaluate(s: Signals) -> Verdict:
    v = Verdict()
    if s.fatal or not s.tls_version:
        v.notes.append("нет рабочего TLS-рукопожатия")
        return v

    high = medium = False
    pts = 0.0

    if s.tls_version == "TLSv1.3":
        pts += 25
    else:
        high = True
        v.notes.append("нет TLS 1.3 — Reality не заработает")

    if s.h2:
        pts += 15
    else:
        medium = True
        v.notes.append("нет h2 в ALPN — браузерный fp ждёт h2")

    if s.mlkem is True:
        pts += 10
    elif s.mlkem is False:
        medium = True
        v.notes.append("target без X25519MLKEM768 — ответ отличается от браузерного")
    if s.mlkem or s.preferred_group == "X25519":
        pts += 5

    if s.cert_matches is True:
        pts += 5
    elif s.cert_matches is False:
        pts -= 10
        high = True
        v.notes.append("сертификат не покрывает SNI")

    if s.redirect_offsite:
        pts -= 25
        high = True
        v.notes.append("редирект на другой хост — Reality-камуфляж ломается")
    elif s.redirect_onsite:
        pts -= 3
        v.notes.append("редирект внутри сайта (допустимо)")
    elif 200 <= s.http_status < 300:
        pts += 5
    elif s.http_status >= 400:
        pts -= 5
        v.notes.append(f"HTTP {s.http_status} на /")

    if s.rtt_avg > 0:
        pts += 5 if s.rtt_avg < 50 else 3 if s.rtt_avg < 150 else 1 if s.rtt_avg < 300 else 0

    # ── топология SNI ↔ IP — главный фактор 2026 ──
    if s.topology == "same_prefix":
        pts += 25
        v.notes.append("донор в той же подсети, что и сервер")
    elif s.topology == "same_asn":
        pts += 20
        v.notes.append("донор в том же ASN, что и сервер")
    elif s.topology == "foreign":
        medium = True
        if s.donor_brand:
            pts -= 15
            high = True
            v.notes.append(f"SNI {s.donor_brand} на IP хостера — несовпадение SNI↔ASN")
        else:
            v.notes.append("донор в другом ASN — ищите соседей по подсети")
    else:
        medium = True
        if s.donor_cloudflare:
            pts -= 15
            high = True
            v.notes.append("донор за Cloudflare — IP VPS не может быть Cloudflare")
        if not s.server_known:
            v.notes.append("IP сервера не задан — топология не оценена")

    if s.overused:
        pts -= 15
        high = True
        v.notes.append("затёртый SNI — в первых строках эвристик ТСПУ")

    if s.profile == PROFILE_WHITELIST:
        if s.ru_whitelisted:
            pts += 15
            v.notes.append("SNI из белого списка РФ")
        else:
            high = True
            v.notes.append("не в белом списке — в режиме белых списков не пройдёт")

    v.score = round(max(0.0, min(pts, 100.0)), 1)
    v.risk = "high" if high else "medium" if medium else "low"
    v.suitable = (v.score >= 50 and s.tls_version == "TLSv1.3" and not s.redirect_offsite
                  and s.cert_matches is not False
                  and not (s.profile == PROFILE_WHITELIST and not s.ru_whitelisted))
    return v


def status_for(score: float) -> str:
    if score >= 80:
        return "ideal"
    if score >= 65:
        return "excellent"
    if score >= 50:
        return "good"
    return "poor"
