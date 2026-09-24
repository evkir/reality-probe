"""Flask-приложение: API + веб-интерфейс."""

import asyncio
import csv
import io
import json
import os
import threading
import time
import zipfile
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from functools import wraps
from typing import Dict

from flask import Flask, Response, jsonify, request

from . import __version__, configgen, runner, sources
from .filters import is_infra_domain, parse_ip, sanitize_domain, sanitize_ip
from .freeze import freeze_test
from .policy import is_excluded
from .prober import ProbeResult
from .scoring import PROFILE_STANDARD, PROFILE_WHITELIST

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# ── rate limiting ─────────────────────────────────────────────────────────────
_rate: Dict[str, list] = defaultdict(list)
_rate_lock = threading.Lock()
RATE_WINDOW = 60
RATE_PROBE = 10
RATE_FREEZE = 6
RATE_API = 120


def rate_limit(limit: int = RATE_API):
    def deco(f):
        @wraps(f)
        def wrapped(*a, **kw):
            key = f"{request.remote_addr or '?'}:{f.__name__}"
            now = time.time()
            with _rate_lock:
                _rate[key] = [t for t in _rate[key] if now - t < RATE_WINDOW]
                if len(_rate[key]) >= limit:
                    return jsonify({"error": "Rate limit exceeded"}), 429
                _rate[key].append(now)
            return f(*a, **kw)
        return wrapped
    return deco


def _int(v, default, lo, hi):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _profile(v) -> str:
    return v if v in (PROFILE_STANDARD, PROFILE_WHITELIST) else PROFILE_STANDARD


def _server_ip(data) -> tuple:
    """(ip, error) — пустая строка допустима, мусор — нет."""
    raw = (data.get("server_ip") or "").strip()
    if not raw:
        return "", None
    ip = parse_ip(raw)
    return (ip, None) if ip else ("", "server_ip: нужен IP-адрес VPS")


def _start(target, mode, *args, **kwargs):
    if not runner.try_start(mode):
        return jsonify({"error": "Already running"}), 400
    threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True).start()
    return None


# ── scans ─────────────────────────────────────────────────────────────────────
@app.route("/api/probe", methods=["POST"])
@rate_limit(RATE_PROBE)
def api_probe():
    data = request.get_json(silent=True) or {}
    raw = data.get("domains") or "\n".join(sources.domain_state["domains"])
    seen, domains = set(), []
    for line in str(raw).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        d = sanitize_domain(line)
        if d and d not in seen:
            seen.add(d)
            domains.append(d)
    if not domains:
        return jsonify({"error": "No domains provided"}), 400
    port = _int(data.get("port"), 443, 1, 65535)
    concurrency = _int(data.get("concurrency"), 15, 1, 40)
    server_ip, err = _server_ip(data)
    if err:
        return jsonify({"error": err}), 400

    scan, pre = [], []
    for d in domains:
        if len(domains) > 1 and is_excluded(d):
            pre.append(asdict(ProbeResult(domain=d, port=port, status="blocked",
                                          blocked_rkn=True, error="Недоступен в РФ — исключён")))
        elif len(domains) > 1 and is_infra_domain(d):
            pre.append(asdict(ProbeResult(domain=d, port=port, status="skipped",
                                          error="Служебная CDN-инфраструктура")))
        else:
            scan.append(d)

    busy = _start(runner.run_scan, "scan", scan, port, concurrency,
                  profile=_profile(data.get("profile")), server_ip=server_ip, pre_results=pre)
    return busy or jsonify({"ok": True, "total": len(domains)})


@app.route("/api/subnet", methods=["POST"])
@rate_limit(RATE_PROBE)
def api_subnet():
    data = request.get_json(silent=True) or {}
    server_ip, err = _server_ip(data)
    if err or not server_ip:
        return jsonify({"error": err or "server_ip обязателен"}), 400
    if ":" in server_ip:
        return jsonify({"error": "сканирование подсети — только IPv4"}), 400
    busy = _start(runner.run_subnet, "subnet", server_ip,
                  _int(data.get("port"), 443, 1, 65535),
                  _int(data.get("concurrency"), 15, 1, 40),
                  prefix_len=_int(data.get("prefix"), 24, 22, 24),
                  profile=_profile(data.get("profile")))
    return busy or jsonify({"ok": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    runner.probe_state["stop_requested"] = True
    return jsonify({"ok": True})


@app.route("/api/status")
def api_status():
    st = runner.probe_state
    return jsonify({
        "running": st["running"], "mode": st["mode"],
        "progress": st["progress"], "total": st["total"],
        "current": st["current_domain"], "elapsed": st["elapsed"],
        "server": st["server"], "profile": st["profile"],
        "neighbors": len(st["neighbors"]),
        "results": sorted(st["results"], key=lambda x: -x.get("score", 0)),
        "log": st["log"][-60:],
    })


@app.route("/api/freeze", methods=["POST"])
@rate_limit(RATE_FREEZE)
def api_freeze():
    data = request.get_json(silent=True) or {}
    sni = sanitize_domain(data.get("sni", ""))
    if not sni:
        return jsonify({"error": "Invalid SNI"}), 400
    target = (data.get("target_ip") or "").strip()
    if target:
        target = parse_ip(target)
        if not target:
            return jsonify({"error": "target_ip: нужен IP-адрес"}), 400
    else:
        import socket
        try:
            target = socket.getaddrinfo(sni, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except OSError as e:
            return jsonify({"error": f"DNS: {e}"}), 400
    path = str(data.get("path") or "/")
    if not path.startswith("/") or any(c in path for c in "\r\n "):
        return jsonify({"error": "path должен начинаться с / без пробелов"}), 400
    res = asyncio.run(freeze_test(target, sni, port=_int(data.get("port"), 443, 1, 65535), path=path))
    return jsonify(res.to_dict())


# ── configs / keys ────────────────────────────────────────────────────────────
@app.route("/api/keygen")
@rate_limit()
def api_keygen():
    import uuid
    priv, pub = configgen.gen_keys()
    return jsonify({"private_key": priv, "public_key": pub,
                    "short_ids": configgen.gen_short_ids(), "uuid": str(uuid.uuid4())})


@app.route("/api/genconfig", methods=["POST"])
@rate_limit()
def api_genconfig():
    data = request.get_json(silent=True) or {}
    domain = sanitize_domain(data.get("domain", ""))
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400
    try:
        cfg = configgen.build(
            domain, _int(data.get("port"), 443, 1, 65535), sanitize_ip(data.get("server_ip", "")),
            transport=data.get("transport") or "tcp",
            fingerprint=data.get("fingerprint") or configgen.FINGERPRINT_DEFAULT)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    # совместимость с v3-клиентами API
    cfg["xray"], cfg["singbox"] = cfg["xray_inbound"], cfg["singbox_inbound"]
    return jsonify(cfg)


# ── domain sources ────────────────────────────────────────────────────────────
@app.route("/api/defaults")
def api_defaults():
    if request.args.get("profile") == PROFILE_WHITELIST:
        lst = sources.WHITELIST_DOMAINS
    else:
        lst = sources.domain_state["domains"]
    return jsonify({"domains": "\n".join(lst), "total": len(lst)})


@app.route("/api/domain-status")
def api_domain_status():
    ds = sources.domain_state
    return jsonify({k: ds[k] for k in ("fetching", "total", "last_update", "sources")})


@app.route("/api/refresh-domains", methods=["POST"])
def api_refresh_domains():
    if sources.domain_state["fetching"]:
        return jsonify({"ok": False, "msg": "Already updating..."})
    sources.refresh_domains_bg()
    return jsonify({"ok": True, "msg": "Update started"})


# ── export ────────────────────────────────────────────────────────────────────
EXPORT_FIELDS = ["domain", "port", "resolved_ip", "donor_asn", "donor_holder", "donor_prefix",
                 "topology", "tls_version", "key_exchange", "mlkem", "h2_supported",
                 "http_status", "redirect_offsite", "redirect_location", "cert_issuer",
                 "cert_days_left", "overused", "ru_whitelisted", "rtt_avg", "score",
                 "tspu_risk", "status", "notes", "error"]


def _sorted_results():
    return sorted(runner.probe_state.get("results", []), key=lambda x: -x.get("score", 0))


def _csv(rows) -> str:
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({**r, "notes": "; ".join(r.get("notes") or [])})
    return out.getvalue()


def _attachment(body, mime, ext):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(body, mimetype=mime, headers={
        "Content-Disposition": f"attachment; filename=reality-probe-{stamp}.{ext}"})


@app.route("/api/export/<fmt>")
@rate_limit()
def api_export(fmt):
    rows = _sorted_results()
    if not rows:
        return jsonify({"error": "No results"}), 404
    if fmt == "csv":
        return _attachment(_csv(rows), "text/csv", "csv")
    meta = {"version": __version__, "timestamp": datetime.now(timezone.utc).isoformat(),
            "server": runner.probe_state.get("server", {}),
            "profile": runner.probe_state.get("profile"), "total": len(rows)}
    if fmt == "json":
        return _attachment(json.dumps({**meta, "results": rows}, indent=2, ensure_ascii=False),
                           "application/json", "json")
    if fmt == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("results.csv", _csv(rows))
            zf.writestr("results.json", json.dumps({**meta, "results": rows}, indent=2, ensure_ascii=False))
            zf.writestr("neighbors.json", json.dumps(runner.probe_state.get("neighbors", []), indent=2))
            low = [r["domain"] for r in rows if r.get("suitable") and r.get("tspu_risk") == "low"]
            ok = [r["domain"] for r in rows if r.get("suitable")]
            zf.writestr("low_risk_domains.txt", "# пригодные, риск ТСПУ низкий\n" + "\n".join(low))
            zf.writestr("suitable_domains.txt", "# пригодные (score>=50)\n" + "\n".join(ok))
        return _attachment(buf.getvalue(), "application/zip", "zip")
    return jsonify({"error": "fmt: csv/json/zip"}), 404


@app.route("/api/history")
@rate_limit()
def api_history():
    return jsonify(runner.load_history())


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


@app.route("/")
def index():
    with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html")
