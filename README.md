<h1 align="center">🐼 Reality Probe v4</h1>

<p align="center">
  <b>SNI/target selection for VLESS Reality under Russia's TSPU DPI policies (2026)</b><br/>
  <sub>SNI↔IP/ASN · neighbors in the VPS subnet · X25519MLKEM768 · 15–20 KB freeze test · Xray / sing-box / Mihomo</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0-00cfee?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.9+-00d47e?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-e8a800?style=flat-square" />
</p>

---

## What changed in TSPU and how v4 responds

TSPU is the DPI system deployed on Russian ISP networks.

| TSPU behavior (2026) | What v4 does |
|---|---|
| TCP freezes after ~15–20 KB / ~25 packets to foreign IPs in datacenter ASNs (Hetzner, DO, Vultr, OVH…) | **Freeze test**: downloads the donor's page through the VPS IP and shows the byte at which the stream stalled. Warns if the server's ASN is in the risk group |
| SNI is checked against the IP owner: an Apple/Microsoft/Google SNI on a hosting IP is an anomaly | **Topology**: donor ASN/prefix vs. the server's (RIPEstat). +25 for the same subnet, +20 for the same ASN, −15 for a big-brand SNI on a foreign ASN, −15 for a donor behind Cloudflare |
| "Burned" SNIs (microsoft.com, apple.com, lovelive-anime.jp…) are at the top of the heuristics | −15 penalty, removed from the built-in list |
| The best donor is a site next to the server | **Subnet neighbors** (like RealiTLScanner): TLS without SNI to every host in the /24 (/23, /22), names from certificates → full probing |
| Browsers send X25519MLKEM768; a target without it gives itself away under active probing | Raw TLS 1.3 ClientHello: selected group + MLKEM support (`KEX` column, `PQ` tag) |
| The `chrome` fingerprint is under suspicion; frequent fp switching → node ban for ~10 min | `firefox` by default, fallback order in the hint, no auto-switching |
| Whitelist mode (mobile networks): TLS passes only with an SNI from the list | **"RU whitelists"** profile: built-in candidates, penalty for everything else |
| Vision does not protect against behavioral analysis | **XHTTP** config (mode auto, padding 100–1000) as a backup inbound |

Without the server IP the maximum is ~70 points (EXCELLENT): the main risk — SNI↔IP mismatch — cannot be assessed, and the tool says so.

---

## Quick start

```bash
git clone https://github.com/evkir/reality-probe.git
cd reality-probe
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python reality_probe.py   # or: .venv/bin/python -m realityprobe --port 7890 --no-browser
```

Open **http://localhost:7890**.

### Workflow

1. Enter the **server (VPS) IP** → click **🧭 Subnet neighbors**. This is the main mode.
2. If the /24 is empty — try /23 or /22, then a regular list scan with the same IP.
3. Filter by **🧭 Subnet/ASN** or **🟢 Low risk** → **USE**.
4. **From a Russian network**, enter the donor in Quick Probe and click **❄ Freeze test** (with the server IP filled in).
   `FROZEN` → change the IP/ASN, not the SNI. Control: the same test with the server IP empty (directly to the donor).
5. Config: transport `TCP + Vision` (primary) and `XHTTP` (backup), fingerprint `firefox`.

---

## Scoring

| Factor | Points |
|---|---|
| TLS 1.3 | +25 (unsuitable without it) |
| h2 in ALPN | +15 |
| X25519MLKEM768 | +10 |
| X25519/MLKEM selected | +5 |
| Certificate covers the SNI | +5 / −10 |
| HTTP 2xx on `/` | +5; off-site redirect −25 (unsuitable) |
| RTT | up to +5 |
| **Donor in the VPS subnet** | **+25** |
| **Donor in the VPS ASN** | **+20** |
| Big-brand SNI on a foreign ASN | −15 |
| Donor behind Cloudflare (ASN unknown) | −15 |
| Burned SNI | −15 |
| "Whitelists" profile: SNI on the list | +15 (otherwise unsuitable) |

Status: **IDEAL** ≥80 · **EXCELLENT** ≥65 · **GOOD** ≥50 · **POOR** <50.
TSPU risk: `LOW` / `MEDIUM` / `HIGH` — hover over the value to see the reasons.

---

## Configs

Xray (server/client), sing-box, Mihomo, NekoBox/Throne, `vless://`:

- `target` instead of the deprecated `dest`, `serverNames` = target host;
- no empty shortId, `fingerprint` on the client only;
- `mux` disabled (incompatible with Vision);
- XHTTP: `flow` is not used; sing-box/Mihomo/NekoBox do not support it — use an Xray-core client (v2rayN, v2rayNG, Happ, Streisand).

---

## Architecture

```
realityprobe/
  policy.py     TSPU policy model: lists, ASNs, Cloudflare ranges, whitelist
  netinfo.py    ASN/prefix via RIPEstat (prefix cache, offline mode)
  tlshello.py   raw ClientHello (X25519MLKEM768) and ServerHello parsing
  certs.py      DER certificate parsing, RFC 6125, MITM issuers
  prober.py     DNS → TLS/ALPN/cert → KEX → HTTP status → ASN → scoring
  scoring.py    pure scoring and risk function
  subnet.py     neighbors in the VPS subnet
  freeze.py     15–20 KB freeze test
  configgen.py  Xray / sing-box / Mihomo / NekoBox / vless://
  runner.py     background scans, history
  app.py        Flask API; web/index.html — UI
```

API: `POST /api/probe`, `POST /api/subnet`, `POST /api/freeze`, `POST /api/genconfig`,
`GET /api/status`, `GET /api/export/{csv,json,zip}`.

---

## Docker

```bash
docker build -t reality-probe .
docker run -p 127.0.0.1:7890:7890 reality-probe
```

The API has no authentication — do not expose the port publicly.

## Tests

```bash
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Tests do not access the internet: a local TLS 1.3 server with a self-signed certificate and a fake RIPEstat.

---

## Limitations

- The TSPU model is a reconstruction from public observations (May–June 2026), not official data; the heuristics change.
- The freeze test is only meaningful from a Russian network; from abroad it will show `CLEAN`.
- The Russian whitelist is unofficial and varies by region.
- Subnet scanning is IPv4 only.

## Related projects

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) · [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) · [SagerNet/sing-box](https://github.com/SagerNet/sing-box)

## License

MIT — see [LICENSE](LICENSE)
