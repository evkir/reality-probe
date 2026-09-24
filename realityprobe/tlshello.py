"""
Сырой TLS 1.3 ClientHello → разбор ServerHello.

Модуль `ssl` не сообщает выбранную группу обмена ключами, а для Reality
в 2026 это важно: uTLS-профили firefox/chrome/safari шлют X25519MLKEM768
(0x11EC). Если target его не поддерживает, ответ target-а при active
probing отличается от того, что видит «легитимный» клиент.

Приватный ключ не нужен: читаем только ServerHello и закрываем сокет.
"""

import asyncio
import os
import struct
from dataclasses import dataclass
from typing import List, Optional

GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017
GROUP_SECP384R1 = 0x0018
GROUP_X25519MLKEM768 = 0x11EC

GROUP_NAMES = {
    GROUP_X25519: "X25519",
    GROUP_SECP256R1: "P-256",
    GROUP_SECP384R1: "P-384",
    GROUP_X25519MLKEM768: "X25519MLKEM768",
}

CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

# SHA-256("HelloRetryRequest") — RFC 8446 §4.1.3
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

MLKEM768_Q = 3329


def mlkem768_encap_key() -> bytes:
    """Структурно валидный ключ инкапсуляции ML-KEM-768 (1184 байта).

    Сервер проверяет, что все коэффициенты < q (FIPS 203 modulus check),
    поэтому просто случайные байты не подходят.
    """
    out = bytearray()
    for _ in range(3 * 256 // 2):
        a = int.from_bytes(os.urandom(2), "big") % MLKEM768_Q
        b = int.from_bytes(os.urandom(2), "big") % MLKEM768_Q
        out += bytes((a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4))
    out += os.urandom(32)  # rho
    return bytes(out)


def _share(group: int) -> bytes:
    if group == GROUP_X25519MLKEM768:
        return mlkem768_encap_key() + os.urandom(32)
    if group == GROUP_X25519:
        return os.urandom(32)
    raise ValueError(f"no key share generator for group {group:#x}")


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _vec16(body: bytes) -> bytes:
    return struct.pack("!H", len(body)) + body


def build_client_hello(sni: str, groups: List[int], share_groups: List[int],
                       alpn: Optional[List[str]] = None) -> bytes:
    alpn = ["h2", "http/1.1"] if alpn is None else alpn
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8]

    exts = b""
    if sni:
        name = sni.encode("idna")
        entry = b"\x00" + _vec16(name)
        exts += _ext(0x0000, _vec16(entry))
    exts += _ext(0x000A, _vec16(b"".join(struct.pack("!H", g) for g in groups)))
    exts += _ext(0x000B, b"\x01\x00")
    sigalgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts += _ext(0x000D, _vec16(b"".join(struct.pack("!H", s) for s in sigalgs)))
    if alpn:
        protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        exts += _ext(0x0010, _vec16(protos))
    exts += _ext(0x002B, b"\x04\x03\x04\x03\x03")          # TLS 1.3, 1.2
    exts += _ext(0x002D, b"\x01\x01")                      # psk_dhe_ke
    shares = b"".join(struct.pack("!H", g) + _vec16(_share(g)) for g in share_groups)
    exts += _ext(0x0033, _vec16(shares))

    body = (b"\x03\x03" + os.urandom(32)
            + b"\x20" + os.urandom(32)
            + _vec16(b"".join(struct.pack("!H", c) for c in ciphers))
            + b"\x01\x00"
            + _vec16(exts))
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _vec16(hs)


@dataclass
class ServerHelloInfo:
    ok: bool = False
    version: str = ""          # "TLSv1.3" / "TLSv1.2"
    cipher: str = ""
    group: Optional[int] = None
    hrr: bool = False          # HelloRetryRequest
    alert: Optional[int] = None
    error: str = ""

    @property
    def group_name(self) -> str:
        if self.group is None:
            return ""
        return GROUP_NAMES.get(self.group, f"0x{self.group:04x}")


def parse_server_hello(data: bytes) -> ServerHelloInfo:
    """Разбирает первую TLS-запись ответа сервера."""
    info = ServerHelloInfo()
    if len(data) < 5:
        info.error = "short read"
        return info
    ctype, _, rlen = data[0], data[1:3], struct.unpack("!H", data[3:5])[0]
    rec = data[5:5 + rlen]
    if ctype == 0x15:
        info.alert = rec[1] if len(rec) >= 2 else None
        info.error = f"alert {info.alert}"
        return info
    if ctype != 0x16 or len(rec) < 4 or rec[0] != 0x02:
        info.error = "not a ServerHello"
        return info
    hlen = int.from_bytes(rec[1:4], "big")
    b = rec[4:4 + hlen]
    try:
        legacy = struct.unpack("!H", b[0:2])[0]
        random = b[2:34]
        sid_len = b[34]
        p = 35 + sid_len
        cipher = struct.unpack("!H", b[p:p + 2])[0]
        p += 3  # cipher + compression
        ext_total = struct.unpack("!H", b[p:p + 2])[0]
        p += 2
        end = p + ext_total
        version = legacy
        while p + 4 <= end:
            et, el = struct.unpack("!HH", b[p:p + 4])
            ed = b[p + 4:p + 4 + el]
            if et == 0x002B and len(ed) >= 2:
                version = struct.unpack("!H", ed[:2])[0]
            elif et == 0x0033 and len(ed) >= 2:
                info.group = struct.unpack("!H", ed[:2])[0]
            p += 4 + el
    except (IndexError, struct.error):
        info.error = "malformed ServerHello"
        return info
    info.hrr = random == HRR_RANDOM
    info.version = {0x0304: "TLSv1.3", 0x0303: "TLSv1.2"}.get(version, f"0x{version:04x}")
    info.cipher = CIPHER_NAMES.get(cipher, f"0x{cipher:04x}")
    info.ok = True
    return info


async def _read_record(reader: asyncio.StreamReader, timeout: float) -> bytes:
    head = await asyncio.wait_for(reader.readexactly(5), timeout)
    rlen = struct.unpack("!H", head[3:5])[0]
    body = await asyncio.wait_for(reader.readexactly(rlen), timeout)
    return head + body


async def hello_probe(host: str, port: int, sni: str, groups: List[int],
                      share_groups: List[int], timeout: float = 4.0) -> ServerHelloInfo:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        writer.write(build_client_hello(sni, groups, share_groups))
        await writer.drain()
        return parse_server_hello(await _read_record(reader, timeout))
    except asyncio.IncompleteReadError:
        return ServerHelloInfo(error="connection closed")
    except asyncio.TimeoutError:
        return ServerHelloInfo(error="timeout")
    except (ConnectionResetError, OSError) as e:
        return ServerHelloInfo(error=f"reset: {e}" if "reset" in str(e).lower() else str(e)[:80])
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.5)
            except Exception:
                pass


@dataclass
class KexReport:
    preferred: str = ""        # группа, выбранная при предложении как у браузера
    mlkem: Optional[bool] = None
    version: str = ""
    cipher: str = ""
    error: str = ""


async def kex_report(host: str, port: int, sni: str, timeout: float = 4.0) -> KexReport:
    """Как target отвечает на ClientHello браузера 2026 (MLKEM + X25519)."""
    rep = KexReport()
    browser = await hello_probe(
        host, port, sni,
        groups=[GROUP_X25519MLKEM768, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
        share_groups=[GROUP_X25519MLKEM768, GROUP_X25519], timeout=timeout)
    if not browser.ok:
        rep.error = browser.error
        return rep
    rep.preferred, rep.version, rep.cipher = browser.group_name, browser.version, browser.cipher
    if browser.group == GROUP_X25519MLKEM768:
        rep.mlkem = True
        return rep
    only = await hello_probe(host, port, sni, groups=[GROUP_X25519MLKEM768],
                             share_groups=[GROUP_X25519MLKEM768], timeout=timeout)
    rep.mlkem = bool(only.ok and only.group == GROUP_X25519MLKEM768)
    return rep
