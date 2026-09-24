"""Фоновые сканы: список доменов и «соседи по подсети». Состояние — в probe_state."""

import asyncio
import json
import os
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List, Optional

from .netinfo import ASNResolver, resolver as default_resolver
from .policy import datacenter
from .prober import ProbeResult, ServerContext, TLSProber
from .scoring import PROFILE_STANDARD
from .subnet import candidate_domains, scan_subnet

SCAN_GLOBAL_TIMEOUT = 900
PROBE_TIMEOUT = 25.0
MAX_SUBNET_CANDIDATES = 200

HISTORY_DIR = os.path.join(os.path.expanduser("~"), ".reality-probe")
HISTORY_FILE = os.path.join(HISTORY_DIR, "scan_history.json")

probe_state = {
    "running": False, "mode": "", "results": [], "progress": 0, "total": 0,
    "current_domain": "", "log": [], "stop_requested": False, "elapsed": 0.0,
    "server": {}, "profile": PROFILE_STANDARD, "neighbors": [],
}
_lock = threading.Lock()


def load_history() -> list:
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return []


def _save_history(results, elapsed):
    try:
        os.makedirs(HISTORY_DIR, exist_ok=True)
        history = load_history()
        history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed": elapsed, "total": len(results),
            "server": probe_state.get("server", {}).get("ip", ""),
            "ideal": sum(1 for r in results if r.get("status") == "ideal"),
            "suitable": sum(1 for r in results if r.get("suitable")),
            "top_domains": [{"domain": r["domain"], "score": r["score"], "status": r["status"]}
                            for r in sorted(results, key=lambda x: -x.get("score", 0))[:10]],
        })
        with open(HISTORY_FILE, "w") as f:
            json.dump(history[-50:], f, indent=2)
    except Exception:
        pass


def _log(line: str):
    probe_state["log"].append(line)
    del probe_state["log"][:-400]


def try_start(mode: str) -> bool:
    """Атомарно занимает раннер; False, если скан уже идёт."""
    with _lock:
        if probe_state["running"]:
            return False
        probe_state.update({
            "running": True, "mode": mode, "stop_requested": False, "results": [],
            "progress": 0, "total": 0, "log": [], "elapsed": 0.0, "neighbors": [],
            "current_domain": "",
        })
        return True


def _stopped() -> bool:
    return bool(probe_state.get("stop_requested"))


def server_context(server_ip: str, asn: ASNResolver) -> ServerContext:
    if not server_ip:
        probe_state["server"] = {}
        return ServerContext()
    info = asn.lookup(server_ip)
    dc = datacenter(info.asn)
    probe_state["server"] = {"ip": server_ip, "asn": info.asn, "prefix": info.prefix,
                             "holder": info.holder, "datacenter": dc or ""}
    if info.asn:
        _log(f"▸ сервер {server_ip}: AS{info.asn} {info.holder} {info.prefix}")
    else:
        _log(f"▸ сервер {server_ip}: ASN не определён (офлайн) — топология по /24")
    if dc:
        _log(f"⚠ {dc} — DC-ASN из группы риска заморозки 15–20 КБ, прогоните тест заморозки")
    return ServerContext(ip=server_ip, info=info)


def _log_result(r: ProbeResult):
    tags = "".join([
        " [H2]" if r.h2_supported else "",
        " [PQ]" if r.mlkem else "",
        " [подсеть]" if r.topology == "same_prefix" else " [ASN]" if r.topology == "same_asn" else "",
        " [затёртый]" if r.overused else "",
        " [⚠REDIR]" if r.redirect_offsite else "",
    ])
    icon = "✦" if r.status == "ideal" else "✓" if r.suitable else \
        "⊘" if r.status in ("blocked", "rst", "tampered") else "·"
    _log(f"{icon} [{probe_state['progress']}/{probe_state['total']}] {r.domain} → "
         f"{r.status.upper()}{tags}" + (f"  rtt={r.rtt_avg:.0f}ms score={r.score}" if r.rtt_avg else "")
         + (f"  {r.error}" if r.error and not r.rtt_avg else ""))


async def _probe_all(prober: TLSProber, domains: List[str], concurrency: int, t0: float):
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(d):
        if _stopped():
            return
        async with sem:
            if _stopped():
                return
            probe_state["current_domain"] = d
            try:
                r = await asyncio.wait_for(prober.probe(d), PROBE_TIMEOUT)
            except asyncio.TimeoutError:
                r = ProbeResult(domain=d, port=prober.port, status="timeout",
                                timeout=True, error="Probe timeout")
            except Exception as e:
                r = ProbeResult(domain=d, port=prober.port, status="error", error=str(e)[:100])
        probe_state["results"].append(asdict(r))
        probe_state["progress"] += 1
        probe_state["elapsed"] = round(time.perf_counter() - t0, 1)
        _log_result(r)

    tasks = [asyncio.ensure_future(one(d)) for d in domains]
    pending = set(tasks)
    while pending:
        _, pending = await asyncio.wait(pending, timeout=0.3)
        if _stopped():
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            break
    if _stopped():
        _log("⏹ Остановлено пользователем")


def _run_loop(coro_factory, t0):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(asyncio.wait_for(coro_factory(), SCAN_GLOBAL_TIMEOUT))
    except asyncio.TimeoutError:
        _log(f"⚠ Глобальный таймаут {SCAN_GLOBAL_TIMEOUT}s — скан прерван")
    except Exception as e:
        _log(f"⚠ Ошибка: {str(e)[:100]}")
    finally:
        pending = asyncio.all_tasks(loop)
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()
        probe_state.update({"running": False, "stop_requested": False, "current_domain": "",
                            "elapsed": round(time.perf_counter() - t0, 1)})
        _log(f"── Готово за {probe_state['elapsed']}s ──")
        _save_history(probe_state["results"], probe_state["elapsed"])


def run_scan(domains: List[str], port: int, concurrency: int, profile: str = PROFILE_STANDARD,
             server_ip: str = "", pre_results: Optional[list] = None,
             asn: Optional[ASNResolver] = None, prober_cls=TLSProber):
    """Вызывать после try_start("scan")."""
    asn = asn or default_resolver
    t0 = time.perf_counter()
    pre_results = pre_results or []
    probe_state.update({"results": list(pre_results), "progress": len(pre_results),
                        "total": len(domains) + len(pre_results), "profile": profile})
    for r in pre_results:
        _log(f"⊘ {r['domain']} → {r['status'].upper()}  {r.get('error', '')}")

    async def main():
        srv = await asyncio.get_running_loop().run_in_executor(None, server_context, server_ip, asn)
        prober = prober_cls(port=port, server=srv, profile=profile, asn=asn, stop=_stopped)
        await _probe_all(prober, domains, concurrency, t0)

    _run_loop(main, t0)


def run_subnet(server_ip: str, port: int, concurrency: int, prefix_len: int = 24,
               profile: str = PROFILE_STANDARD, asn: Optional[ASNResolver] = None,
               prober_cls=TLSProber, network=None):
    """Вызывать после try_start("subnet"). Фаза 1: TLS-соседи; фаза 2: полный пробинг имён."""
    asn = asn or default_resolver
    t0 = time.perf_counter()
    probe_state["profile"] = profile

    async def main():
        srv = await asyncio.get_running_loop().run_in_executor(None, server_context, server_ip, asn)
        _log(f"▸ фаза 1: TLS-соседи {server_ip}/{prefix_len}")

        def progress(done, total):
            probe_state["progress"], probe_state["total"] = done, total
            probe_state["elapsed"] = round(time.perf_counter() - t0, 1)

        neighbors = await scan_subnet(server_ip, port=port, prefix_len=prefix_len,
                                      concurrency=max(concurrency, 32), stop=_stopped,
                                      on_progress=progress, network=network)
        probe_state["neighbors"] = [n.to_dict() for n in neighbors]
        tls13 = sum(1 for n in neighbors if n.tls_version == "TLSv1.3")
        _log(f"▸ найдено TLS-хостов: {len(neighbors)} (TLS 1.3: {tls13})")
        domains = candidate_domains(neighbors)[:MAX_SUBNET_CANDIDATES]
        if not domains or _stopped():
            _log("⚠ в подсети нет пригодных TLS 1.3 доноров — попробуйте /23 или /22")
            return
        _log(f"▸ фаза 2: пробинг {len(domains)} имён из сертификатов")
        probe_state.update({"progress": 0, "total": len(domains)})
        prober = prober_cls(port=port, server=srv, profile=profile, asn=asn, stop=_stopped)
        await _probe_all(prober, domains, concurrency, t0)

    _run_loop(main, t0)
