"""python -m realityprobe [--host H] [--port P] [--no-browser]"""

import argparse
import os
import signal
import threading
import time
import webbrowser

from . import __version__, runner, sources
from .app import app


def main(argv=None):
    ap = argparse.ArgumentParser(prog="reality-probe", description=__doc__)
    ap.add_argument("--host", default=os.environ.get("RP_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("RP_PORT", "7890")))
    ap.add_argument("--no-browser", action="store_true",
                    default=os.environ.get("RP_NO_BROWSER") == "1")
    args = ap.parse_args(argv)

    def _sig(sig, frame):
        print("\n  Shutting down...")
        runner.probe_state["stop_requested"] = True
        time.sleep(0.5)
        os._exit(0)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    print(f"\n  Reality Probe v{__version__} — ТСПУ 2026")
    print("  ─────────────────────────────────────────────")
    print(f"  ► http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}")
    print("  • топология SNI↔IP/ASN, соседи по подсети VPS")
    print("  • X25519MLKEM768, тест заморозки 15–20 КБ")
    print("  • конфиги: firefox fp, target, XHTTP\n")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("  ⚠ слушаю не только localhost — API без авторизации, закройте порт фаерволом\n")
    sources.refresh_domains_bg()
    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(1.2),
                                         webbrowser.open(f"http://localhost:{args.port}")),
                         daemon=True).start()
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
