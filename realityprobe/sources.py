"""
Источники доменов-кандидатов.

В 2026 внешние топ-листы — второстепенный источник: лучший донор ищется
в подсети VPS (subnet.py). Встроенный список очищен от «затёртых» SNI.
"""

import csv
import io
import json
import re
import threading
import urllib.request
from datetime import datetime, timezone

from .filters import is_suitable_for_scan, looks_like_cdn
from .policy import RU_WHITELIST_SUFFIXES, is_excluded, is_overused

class DomainFetcher:
    TIMEOUT = 12

    # ── jsDelivr (Cloudflare CDN) — CDN-specific files only ─────────────
    # Skip loyalsoldier/direct — 100k+ unfiltered domains
    JSDELIVR_SOURCES = [
        # v2fly/cdn — curated CDN domains (small list)
        ("v2fly/cdn",
         "https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/cdn"),
        # XTLS RealiTLScanner — Reality-compatible verified domains
        ("XTLS/scanner",
         "https://cdn.jsdelivr.net/gh/XTLS/RealiTLScanner@main/domains.txt"),
        # Loyalsoldier PROXY list (external CDN)
        ("loyalsoldier/proxy",
         "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"),
        # ACL4SSR foreign CDN list
        ("acl4ssr/foreign",
         "https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/providers/ProxyMedia.yaml"),
    ]

    GITHUB_FALLBACK = [
        ("github/v2fly-cdn",
         "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cdn"),
        ("github/RealiTLScanner",
         "https://raw.githubusercontent.com/XTLS/RealiTLScanner/main/domains.txt"),
    ]

    # ── Majestic Million — good top-sites list ────────────────
    MAJESTIC_URLS = [
        "https://downloads.majestic.com/majestic_million.csv",
        # jsDelivr mirror as fallback
        "https://cdn.jsdelivr.net/gh/dhamaniasad/top-1m-domains@master/majestic_million.csv",
    ]

    # ── Cloudflare Radar — current API ────────────────────────────────
    RADAR_URLS = [
        # Current working endpoint (CSV attachment)
        "https://radar.cloudflare.com/charts/LargerTopDomainsTable/attachment?id=942&top=500",
        "https://radar.cloudflare.com/charts/LargerTopDomainsTable/attachment?top=500",
        # Via API
        "https://api.cloudflare.com/client/v4/radar/domains/top?limit=500&format=csv",
    ]

    # ── Certspotter (alternative to crt.sh) ─────────────
    CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names&limit=100"
    CERTSPOTTER_DOMAINS = [
        "akamai.com", "fastly.com", "cloudflare.com", "microsoft.com",
        "apple.com", "google.com", "github.com", "twitch.tv",
    ]

    # ── Large hardcoded fallback (works FULLY OFFLINE) ─────────────────
    OFFLINE_FALLBACK = [
        # Microsoft
        "www.microsoft.com","login.microsoftonline.com","dl.delivery.mp.microsoft.com",
        "download.microsoft.com","aka.ms","azure.microsoft.com","docs.microsoft.com",
        "learn.microsoft.com","go.microsoft.com","www.office.com","onedrive.live.com",
        "www.bing.com","assets.msn.com","www.nuget.org","api.nuget.org",
        "packages.microsoft.com","visualstudio.com","dev.azure.com","vsassets.io",
        # Apple
        "www.apple.com","apps.apple.com","developer.apple.com","support.apple.com",
        "updates.cdn-apple.com","swdist.apple.com","swdownload.apple.com",
        "devimages-cdn.apple.com","is1-ssl.mzstatic.com","is2-ssl.mzstatic.com",
        "itunes.apple.com","swscan.apple.com","lcdn-registration.apple.com",
        # Google CDN
        "dl.google.com","storage.googleapis.com","ajax.googleapis.com",
        "fonts.googleapis.com","fonts.gstatic.com","www.gstatic.com","ssl.gstatic.com",
        "lh3.googleusercontent.com","yt3.ggpht.com","www.googletagmanager.com",
        "www.google-analytics.com","pagead2.googlesyndication.com",
        # Cloudflare
        "www.cloudflare.com","speed.cloudflare.com","blog.cloudflare.com",
        "developers.cloudflare.com","cdnjs.cloudflare.com","api.cloudflare.com",
        "one.one.one.one",
        # jsDelivr / unpkg
        "cdn.jsdelivr.net","fastly.jsdelivr.net","gcore.jsdelivr.net","unpkg.com",
        # Fastly
        "www.fastly.com","api.fastly.com","global.fastly.net",
        # GitHub
        "github.com","api.github.com","raw.githubusercontent.com",
        "objects.githubusercontent.com","codeload.github.com","ghcr.io",
        "gist.github.com","docs.github.com",
        # npm
        "registry.npmjs.org","www.npmjs.com",
        # Adobe
        "www.adobe.com","helpx.adobe.com","typekit.net","use.typekit.net",
        # Oracle / IBM / Salesforce
        "www.oracle.com","download.oracle.com","docs.oracle.com",
        "www.ibm.com","developer.ibm.com","cloud.ibm.com",
        "www.salesforce.com","trailhead.salesforce.com",
        "static.salesforceusercontent.com",
        # Dropbox / Box
        "www.dropbox.com","dl.dropboxusercontent.com","www.box.com",
        # Akamai
        "dl.akamaized.net","download.akamaized.net","akamaiapis.net",
        "a248.e.akamai.net",
        # Twitch
        "www.twitch.tv","static.twitchsvc.net","vod-secure.twitch.tv",
        "clips-media-assets2.twitch.tv",
        # Bunny/CDN77
        "cdn77.com","b-cdn.net","bunnycdn.com","keycdn.com",
        # Wikimedia
        "upload.wikimedia.org","commons.wikimedia.org","meta.wikimedia.org",
        # Mozilla
        "www.mozilla.org","download.mozilla.org","releases.mozilla.org",
        "addons.mozilla.org","cdn.mozilla.net",
        # JetBrains
        "www.jetbrains.com","download.jetbrains.com","cache-redirector.jetbrains.com",
        "plugins.jetbrains.com",
        # Valve/Steam
        "store.steampowered.com","cdn.akamai.steamstatic.com","steamcdn-a.akamaihd.net",
        "steamcommunity.com",
        # 1Password / Bitwarden
        "1password.com","vault.bitwarden.com",
        # Slack
        "slack.com","a.slack-edge.com",
        # Figma / Notion / Vercel
        "www.figma.com","cdn.figma.com","www.notion.so","vercel.com","netlify.com",
        # PyPI / Docker / HashiCorp / Elastic
        "pypi.org","files.pythonhosted.org","hub.docker.com","production.cloudflare.docker.com",
        "releases.hashicorp.com","registry.terraform.io","artifacts.elastic.co",
        # Go / Rust / Java
        "golang.org","static.rust-lang.org","crates.io","repo1.maven.org",
        "search.maven.org","services.gradle.org","downloads.gradle.org",
        # Nginx / Apache
        "nginx.org","downloads.apache.org",
        # DigitalOcean / Hetzner / Linode
        "cdn.digitalocean.com","www.hetzner.com","download.hetzner.com",
        # Cloudflare Workers/R2
        "workers.cloudflare.com","pages.cloudflare.com",
        # AWS docs (not CloudFront)
        "d1.awsstatic.com","docs.aws.amazon.com",
        # Anaconda
        "repo.anaconda.com","conda.anaconda.org",
        # Nginx/Caddy docs
        "caddyserver.com","www.nginx.com",
        # Stripe / Twilio (CDN infrastructure)
        "js.stripe.com","api.stripe.com","assets.twilio.com",
        # Shopify CDN
        "cdn.shopify.com","assets.shopify.com",
        # Intercom
        "js.intercomcdn.com","widget.intercom.io",
        # Zendesk
        "static.zdassets.com","ekr.zdassets.com",
        # HubSpot
        "js.hs-scripts.com","js.hubspot.com",
        # Let's Encrypt OCSP
        "r3.o.lencr.org","x1.i.lencr.org","o.lencr.org",
    ]

    CRTSH_ORGS = [
        "Akamai Technologies", "Fastly", "Cloudflare",
        "Apple Inc.", "Microsoft Corporation", "Google LLC",
    ]

    @staticmethod
    def _get(url: str, timeout: int = 12) -> bytes:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            enc = r.info().get("Content-Encoding", "")
            if "gzip" in enc:
                import gzip; data = gzip.decompress(data)
            elif "br" in enc:
                pass  # brotli — skip, rare
            return data

    @staticmethod
    def _classify_error(e: Exception, url: str = "") -> str:
        es  = str(e).lower()
        host = url.split("/")[2] if "/" in url else url
        if "timed out" in es or "timeout" in es:
            return f"timeout [{host}]"
        if "connection refused" in es:
            return f"refused [{host}]"
        if "getaddrinfo" in es or "name or service" in es:
            return f"DNS [{host}]"
        if "403" in es: return f"403 [{host}]"
        if "404" in es: return f"404 [{host}]"
        if "ssl" in es or "certificate" in es: return f"TLS [{host}]"
        return f"{str(e)[:40]} [{host}]"

    @staticmethod
    def _parse_domain_lines(raw: str, cdn_only: bool = False) -> list:
        """
        Parses domains from plain/v2fly/YAML/Clash formats.
        cdn_only=True: accept only domains with CDN indicators.
        """
        domains = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            # v2fly formats
            if line.startswith("full:"):    line = line[5:].strip()
            elif line.startswith("include:"): continue
            elif line.startswith("regexp:"): continue
            elif line.startswith("keyword:"): continue
            # YAML/Clash: "  - domain" or "  - DOMAIN-SUFFIX,domain,policy"
            if line.startswith("- "):
                line = line[2:].strip()
                if "," in line:
                    parts = line.split(",")
                    line = parts[1].strip() if len(parts) > 1 else ""
            # inline comments
            if "#" in line: line = line[:line.index("#")].strip()
            # clean whitespace / quotes
            line = line.strip("'\"").strip()
            if not line or " " in line or len(line) < 4: continue
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{2,253}$', line): continue
            if '.' not in line: continue
            d = line.lower()
            if cdn_only and not looks_like_cdn(d): continue
            domains.append(d)
        return domains

    def fetch_github(self) -> tuple:
        """jsDelivr CDN → fallback github. Apply CDN filter."""
        collected = []
        ok_list, fail_list = [], []

        for name, url in self.JSDELIVR_SOURCES:
            try:
                raw   = self._get(url, timeout=self.TIMEOUT).decode("utf-8", errors="ignore")
                # CDN filter: v2fly/cdn already filtered, loyalsoldier/proxy — not
                cdn_only = "loyalsoldier" in name or "acl4ssr" in name
                found = self._parse_domain_lines(raw, cdn_only=cdn_only)
                found = [d for d in found if is_suitable_for_scan(d)]
                if found:
                    collected.extend(found)
                    ok_list.append(f"{name}(+{len(found)})")
            except Exception as e:
                fail_list.append(self._classify_error(e, url))

        if len(collected) < 30:
            for name, url in self.GITHUB_FALLBACK:
                try:
                    raw   = self._get(url, timeout=self.TIMEOUT).decode("utf-8", errors="ignore")
                    found = self._parse_domain_lines(raw)
                    found = [d for d in found if is_suitable_for_scan(d)]
                    if found:
                        collected.extend(found); ok_list.append(f"{name}(+{len(found)})"); break
                except Exception as e:
                    fail_list.append(self._classify_error(e, url))

        seen = set()
        filtered = [d for d in collected if not (d in seen or seen.add(d))]
        if filtered:
            msg = f"loaded {len(filtered)} [{', '.join(ok_list[:2])}]"
        else:
            msg = f"⚠ unavailable ({'; '.join(fail_list[:2])})"
        return filtered, msg

    def fetch_majestic(self) -> tuple:
        """
        Majestic Million top-1M sites.
        Take top-5000, filter by CDN indicators.
        """
        for url in self.MAJESTIC_URLS:
            try:
                raw  = self._get(url, timeout=20).decode("utf-8", errors="ignore")
                reader = csv.reader(io.StringIO(raw))
                next(reader, None)  # skip header
                domains = []
                for i, row in enumerate(reader):
                    if i >= 5000: break
                    # format: GlobalRank,TldRank,Domain,TLD,...
                    if len(row) < 3: continue
                    domain = row[2].strip().lower()
                    if not domain or '.' not in domain: continue
                    if is_excluded(domain): continue
                    if looks_like_cdn(domain): domains.append(domain)
                if domains:
                    return domains, f"loaded {len(domains)} CDN from Majestic top-5k"
            except Exception as e:
                pass
        return [], "⚠ Majestic unavailable"

    def fetch_cloudflare_radar(self) -> tuple:
        """Cloudflare Radar — try all endpoints."""
        for url in self.RADAR_URLS:
            try:
                raw = self._get(url, timeout=10).decode("utf-8", errors="ignore")
                domains = []
                # JSON?
                if raw.strip().startswith(("{", "[")):
                    try:
                        data = json.loads(raw)
                        items = data if isinstance(data, list) else \
                                data.get("result", data.get("data", data.get("rows", [])))
                        for item in (items if isinstance(items, list) else []):
                            d = (item.get("domain") or item.get("name") or "").lower()
                            if d and '.' in d and not is_excluded(d):
                                domains.append(d)
                    except Exception:
                        pass
                else:
                    # CSV
                    for row in csv.reader(io.StringIO(raw)):
                        for cell in row:
                            c = cell.strip().lower()
                            if re.match(r'^[a-z0-9][a-z0-9\-\.]{3,60}$', c) and '.' in c \
                               and not is_excluded(c):
                                domains.append(c); break
                if len(domains) > 20:
                    return domains, f"loaded {len(domains)} from Cloudflare Radar"
            except Exception:
                continue

        # Hardcoded fallback
        filtered = [d for d in self.OFFLINE_FALLBACK if not is_excluded(d)]
        seen = set()
        filtered = [d for d in filtered if not (d in seen or seen.add(d))]
        return filtered, f"offline fallback ({len(filtered)} domains)"

    def fetch_certspotter(self) -> tuple:
        """
        Certspotter — alternative to crt.sh.
        Search for CDN provider subdomains.
        """
        import urllib.parse
        collected = set()
        ok, errors = 0, 0
        for domain in self.CERTSPOTTER_DOMAINS:
            try:
                url = self.CERTSPOTTER_URL.format(domain)
                raw = self._get(url, timeout=8)
                entries = json.loads(raw)
                for entry in entries:
                    for name in entry.get("dns_names", []):
                        name = name.strip().lstrip("*.")
                        if not name or '.' not in name or '*' in name: continue
                        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{2,253}$', name):
                            d = name.lower()
                            if not is_excluded(d) and looks_like_cdn(d):
                                collected.add(d)
                ok += 1
            except Exception as e:
                errors += 1
                if errors >= 3: break  # bail quickly if unavailable

        result = list(collected)
        if result:
            return result, f"found {len(result)} from certspotter"
        # fallback: crt.sh with short timeout
        return self._fetch_crtsh_quick()

    def _fetch_crtsh_quick(self) -> tuple:
        """crt.sh with short timeout — skip quickly if unavailable."""
        import urllib.parse
        collected = set()
        for org in self.CRTSH_ORGS[:4]:  # only 4 orgs, quick
            try:
                url = f"https://crt.sh/?O={urllib.parse.quote(org)}&output=json&limit=30"
                raw = self._get(url, timeout=5)
                for entry in json.loads(raw):
                    name = entry.get("common_name", "") or entry.get("name_value", "")
                    for part in name.split("\n"):
                        part = part.strip().lstrip("*.")
                        if part and '.' in part and '*' not in part:
                            d = part.lower()
                            if not is_excluded(d) and looks_like_cdn(d):
                                collected.add(d)
            except Exception:
                pass
        result = list(collected)
        if result:
            return result, f"found {len(result)} via crt.sh"
        return [], "⚠ CT logs unavailable"

    def fetch_all(self):
        results = {
            "github":  ([], ""),
            "tranco":  ([], ""),   # renamed to majestic internally
            "radar":   ([], ""),
            "crtsh":   ([], ""),
        }

        def _run(key, fn):
            try:    results[key] = fn()
            except Exception as e: results[key] = ([], f"exception: {e}")

        threads = [
            threading.Thread(target=_run, args=("github",  self.fetch_github),       daemon=True),
            threading.Thread(target=_run, args=("tranco",  self.fetch_majestic),     daemon=True),
            threading.Thread(target=_run, args=("radar",   self.fetch_cloudflare_radar), daemon=True),
            threading.Thread(target=_run, args=("crtsh",   self.fetch_certspotter),  daemon=True),
        ]
        for t in threads: t.start()
        for t in threads: t.join(timeout=40)

        seen, merged = set(), []
        for d in BUILTIN_DOMAINS:
            if d not in seen: seen.add(d); merged.append(d)

        for key in ("github", "tranco", "radar", "crtsh"):
            domains, msg = results[key]
            domain_state["sources"][key] = {
                "count": len(domains), "ok": len(domains) > 0, "msg": msg}
            for d in domains:
                if d not in seen and is_suitable_for_scan(d) and not is_overused(d):
                    seen.add(d); merged.append(d)

        domain_state["domains"]     = merged
        domain_state["total"]       = len(merged)
        domain_state["last_update"] = datetime.now(timezone.utc).isoformat()
        domain_state["fetching"]    = False
        domain_state["sources"]["builtin"]["count"] = len(BUILTIN_DOMAINS)

        ok  = [k for k in ("github","tranco","radar","crtsh") if results[k][0]]
        bad = [k for k in ("github","tranco","radar","crtsh") if not results[k][0]]
        total_new = len(merged) - len(BUILTIN_DOMAINS)
        print(f"  🐼 Domains: {len(merged)} ({total_new} external)")
        if ok:  print(f"     ✓ {', '.join(ok)}")
        if bad: print(f"     ⚠ {', '.join(bad)}")
        return merged


def _clean(domains):
    seen, out = set(), []
    for d in domains:
        if d in seen or is_excluded(d) or is_overused(d) or not is_suitable_for_scan(d):
            continue
        seen.add(d)
        out.append(d)
    return out


BUILTIN_DOMAINS = _clean(DomainFetcher.OFFLINE_FALLBACK)

# Кандидаты для профиля «белые списки»: главные хосты из ядра списка
WHITELIST_DOMAINS = [
    "ya.ru", "yandex.ru", "dzen.ru", "yastatic.net", "kinopoisk.ru",
    "vk.com", "vk.ru", "mail.ru", "ok.ru", "max.ru", "rutube.ru",
    "www.gosuslugi.ru", "www.mos.ru", "www.ozon.ru", "www.wildberries.ru",
    "www.avito.ru", "www.sberbank.ru", "www.tbank.ru", "www.vtb.ru",
    "alfabank.ru", "www.pochta.ru", "www.rzd.ru", "2gis.ru", "hh.ru",
    "www.kaspersky.ru",
]
assert all(any(d == s or d.endswith("." + s) for s in RU_WHITELIST_SUFFIXES)
           for d in WHITELIST_DOMAINS)

domain_state = {
    "domains":     list(BUILTIN_DOMAINS),
    "fetching":    False,
    "last_update": None,
    "sources": {
        "builtin": {"count": len(BUILTIN_DOMAINS), "ok": True,  "msg": "офлайн, без затёртых SNI"},
        "github":  {"count": 0, "ok": None, "msg": "jsDelivr CDN"},
        "radar":   {"count": 0, "ok": None, "msg": "Cloudflare Radar top-500"},
        "tranco":  {"count": 0, "ok": None, "msg": "Majestic Million top-5k CDN"},
        "crtsh":   {"count": 0, "ok": None, "msg": "Certspotter / crt.sh CT logs"},
    },
    "total": len(BUILTIN_DOMAINS),
}


def refresh_domains_bg():
    if domain_state["fetching"]:
        return
    domain_state["fetching"] = True

    def run():
        try:
            DomainFetcher().fetch_all()
        finally:
            domain_state["fetching"] = False
    threading.Thread(target=run, daemon=True).start()
