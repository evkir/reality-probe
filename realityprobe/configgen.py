"""
Генерация конфигов VLESS Reality (2026).

Изменения относительно v3:
- fingerprint по умолчанию firefox (chrome 13x под подозрением ТСПУ);
- `target` вместо устаревшего `dest`, serverNames строго = хост target;
- из серверного realitySettings убран `fingerprint` (это клиентское поле);
- пустой shortId больше не разрешается (вход без shortId = слабее);
- транспорт XHTTP как альтернатива TCP+Vision: upload/download разнесены
  по разным HTTP-транзакциям + padding, flow не используется;
- mux выключен (несовместим с Vision).
"""

import base64
import secrets
import urllib.parse as up
import uuid
from typing import Dict, List

from .policy import FINGERPRINT_DEFAULT, FINGERPRINTS_RECOMMENDED

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)
    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    HAS_CRYPTO = False

TRANSPORTS = ("tcp", "xhttp")
FINGERPRINTS = set(FINGERPRINTS_RECOMMENDED) | {"ios", "android", "random", "360"}
FLOW_VISION = "xtls-rprx-vision"
XHTTP_PADDING = "100-1000"


def gen_keys():
    if not HAS_CRYPTO:
        return "<install cryptography>", "<install cryptography>"
    pk = X25519PrivateKey.generate()

    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return (b64u(pk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            b64u(pk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))


def gen_short_ids() -> List[str]:
    """Несколько непустых shortId разной длины (hex, чётная длина ≤ 16)."""
    return [secrets.token_hex(n) for n in (4, 6, 8, 8)]


def _xhttp_path() -> str:
    return "/" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:10].lower()


def build(domain: str, port: int, server_ip: str, transport: str = "tcp",
          fingerprint: str = FINGERPRINT_DEFAULT, listen_port: int = 443) -> Dict:
    if transport not in TRANSPORTS:
        raise ValueError(f"transport: {', '.join(TRANSPORTS)}")
    if fingerprint not in FINGERPRINTS:
        raise ValueError("unknown fingerprint")

    priv, pub = gen_keys()
    short_ids = gen_short_ids()
    sid = short_ids[0]
    uid = str(uuid.uuid4())
    xhttp = transport == "xhttp"
    flow = "" if xhttp else FLOW_VISION
    path = _xhttp_path() if xhttp else ""
    name = f"reality-{domain[:20]}"

    stream_server = {
        "network": "xhttp" if xhttp else "tcp",
        "security": "reality",
        "realitySettings": {
            "show": False,
            "target": f"{domain}:{port}",
            "xver": 0,
            "serverNames": [domain],
            "privateKey": priv,
            "shortIds": short_ids,
            "maxTimeDiff": 60000,
        },
    }
    stream_client = {
        "network": stream_server["network"],
        "security": "reality",
        "realitySettings": {
            "serverName": domain,
            "fingerprint": fingerprint,
            "publicKey": pub,
            "shortId": sid,
            "spiderX": "/",
        },
    }
    if xhttp:
        stream_server["xhttpSettings"] = {"path": path, "mode": "auto",
                                          "extra": {"xPaddingBytes": XHTTP_PADDING}}
        stream_client["xhttpSettings"] = {"path": path, "mode": "auto"}

    client = {"id": uid, "email": "client-1"}
    if flow:
        client["flow"] = flow
    xray_inbound = {"inbounds": [{
        "tag": "vless-reality-in", "listen": "0.0.0.0", "port": listen_port,
        "protocol": "vless",
        "settings": {"clients": [client], "decryption": "none"},
        "streamSettings": stream_server,
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
    }]}

    user = {"id": uid, "encryption": "none", "level": 0}
    if flow:
        user["flow"] = flow
    xray_outbound = {"outbounds": [{
        "tag": "proxy-reality", "protocol": "vless",
        "settings": {"vnext": [{"address": server_ip, "port": listen_port, "users": [user]}]},
        "streamSettings": stream_client,
        "mux": {"enabled": False},
    }]}

    unsupported = {"_unsupported": "sing-box/Mihomo/NekoBox не поддерживают XHTTP — "
                                   "используйте клиент на Xray-core (v2rayN, v2rayNG, Happ, Streisand)"}
    if xhttp:
        sb_inbound = sb_outbound = nekobox = unsupported
        mihomo = "# " + unsupported["_unsupported"]
    else:
        sb_inbound = {"inbounds": [{
            "type": "vless", "tag": "vless-reality-in", "listen": "::",
            "listen_port": listen_port,
            "users": [{"uuid": uid, "flow": flow, "name": "client-1"}],
            "tls": {"enabled": True, "server_name": domain,
                    "reality": {"enabled": True,
                                "handshake": {"server": domain, "server_port": port},
                                "private_key": priv, "short_id": short_ids,
                                "max_time_difference": "1m"}},
        }]}
        sb_outbound = {"outbounds": [{
            "type": "vless", "tag": "proxy-reality", "server": server_ip,
            "server_port": listen_port, "uuid": uid, "flow": flow,
            "tls": {"enabled": True, "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": fingerprint},
                    "reality": {"enabled": True, "public_key": pub, "short_id": sid}},
        }]}
        mihomo = (
            "proxies:\n"
            f"  - name: {name}\n"
            "    type: vless\n"
            f"    server: {server_ip}\n"
            f"    port: {listen_port}\n"
            f"    uuid: {uid}\n"
            "    network: tcp\n"
            "    tls: true\n"
            "    udp: true\n"
            f"    flow: {flow}\n"
            f"    servername: {domain}\n"
            "    reality-opts:\n"
            f"      public-key: {pub}\n"
            f"      short-id: {sid}\n"
            f"    client-fingerprint: {fingerprint}\n"
            "\n# Mihomo / Clash Verge Rev / FlClash. mux выключен (несовместим с Vision)"
        )
        nekobox = {
            "v": "2", "type": "vless", "name": name, "add": server_ip,
            "port": listen_port, "id": uid, "flow": flow, "scy": "none",
            "net": "tcp", "tls": "reality", "sni": domain, "fp": fingerprint,
            "pbk": pub, "sid": sid, "spx": "/",
        }

    q = {"encryption": "none", "security": "reality", "sni": domain,
         "fp": fingerprint, "pbk": pub, "sid": sid, "spx": "/"}
    if xhttp:
        q.update({"type": "xhttp", "path": path, "mode": "auto"})
    else:
        q.update({"type": "tcp", "flow": flow, "headerType": "none"})
    share_uri = f"vless://{uid}@{server_ip}:{listen_port}?{up.urlencode(q)}#{up.quote(name)}"

    return {
        "xray_inbound": xray_inbound, "xray_outbound": xray_outbound,
        "singbox_inbound": sb_inbound, "singbox_outbound": sb_outbound,
        "mihomo": mihomo, "nekoray": nekobox, "share_uri": share_uri,
        "panel_note": panel_note(domain, transport, fingerprint),
        "public_key": pub, "private_key": priv, "uuid": uid,
        "short_ids": short_ids, "domain": domain, "port": port,
        "transport": transport, "fingerprint": fingerprint, "flow": flow,
        "xhttp_path": path,
    }


def panel_note(domain: str, transport: str, fingerprint: str) -> str:
    fps = " → ".join(FINGERPRINTS_RECOMMENDED)
    return (
        "# 3x-ui / Marzban / Remnawave: Inbounds → Add, поля как в Xray inbound\n\n"
        f"# target: {domain}   transport: {transport}   fingerprint: {fingerprint}\n\n"
        "# ТСПУ 2026 — что важно:\n"
        "# 1. target в той же подсети/ASN, что и VPS (кнопка «Соседи /24»).\n"
        "#    SNI Apple/Microsoft/Google на IP хостера = несовпадение SNI↔IP.\n"
        "# 2. Заморозка ~15–20 КБ на DC-ASN: прогоните «Тест заморозки» из РФ.\n"
        "#    Замерзает — меняйте IP/ASN, а не SNI.\n"
        f"# 3. Fingerprint: {fps}. Не переключайте fp часто под нагрузкой —\n"
        "#    это даёт бан узла ~10 минут.\n"
        "# 4. Vision (tcp) не спасает от поведенческого анализа — держите\n"
        "#    запасной inbound на XHTTP (padding 100-1000).\n"
        "# 5. Только порт 443/TCP, mux выключен, без пустого shortId.\n"
        "# 6. В режиме белых списков — только SNI из белого списка РФ\n"
        "#    и, как правило, IP внутри РФ."
    )
