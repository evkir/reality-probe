"""
Тест заморозки ТСПУ (2026): на TCP к «подозрительным» зарубежным IP
соединение подмораживается после ~15–20 КБ / ~25 пакетов сервер→клиент.

Как пользоваться: запускать ИЗ сети РФ против IP своего VPS с SNI донора.
Reality-сервер отдаёт неаутентифицированным клиентам контент target-а,
поэтому мы качаем страницу донора «через» VPS и смотрим, где встанет поток.
Контроль: тот же тест напрямую на IP донора — он не должен замерзать.
"""

import asyncio
import ssl
import time
from dataclasses import dataclass, asdict

from .policy import FREEZE_MAX_BYTES, FREEZE_MIN_BYTES

READ_CAP = 96 * 1024


@dataclass
class FreezeResult:
    target_ip: str
    sni: str
    bytes_received: int = 0
    completed: bool = False        # сервер закрыл/отдал всё
    stalled: bool = False
    stall_at: int = 0
    elapsed: float = 0.0
    verdict: str = ""              # frozen / clean / inconclusive / error
    note: str = ""
    error: str = ""

    def to_dict(self):
        return asdict(self)


def classify(bytes_received: int, completed: bool, stalled: bool) -> tuple:
    if stalled and FREEZE_MIN_BYTES <= bytes_received <= FREEZE_MAX_BYTES:
        return "frozen", "поток встал в окне 12–24 КБ — типичная заморозка ТСПУ по IP/ASN"
    if stalled:
        return "inconclusive", f"поток встал на {bytes_received} Б — вне окна заморозки"
    if bytes_received > FREEZE_MAX_BYTES:
        return "clean", "прошло больше 24 КБ без остановки"
    if completed:
        return "inconclusive", "ответ донора меньше 24 КБ — укажите путь к большому файлу"
    return "inconclusive", "недостаточно данных"


async def freeze_test(target_ip: str, sni: str, port: int = 443, path: str = "/",
                      stall_timeout: float = 6.0, total_timeout: float = 30.0,
                      verify: bool = False) -> FreezeResult:
    res = FreezeResult(target_ip=target_ip, sni=sni)
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    t0 = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port, ssl=ctx, server_hostname=sni,
                                    ssl_handshake_timeout=stall_timeout),
            stall_timeout + 1)
        req = (f"GET {path} HTTP/1.1\r\nHost: {sni}\r\n"
               "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0\r\n"
               "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        while res.bytes_received < READ_CAP:
            if time.perf_counter() - t0 > total_timeout:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(16384), stall_timeout)
            except asyncio.TimeoutError:
                res.stalled, res.stall_at = True, res.bytes_received
                break
            if not chunk:
                res.completed = True
                break
            res.bytes_received += len(chunk)
    except asyncio.TimeoutError:
        res.error = "handshake timeout"
    except (ConnectionResetError, ssl.SSLError, OSError) as e:
        res.error = str(e)[:120] or type(e).__name__
        if res.bytes_received:              # обрыв посреди потока ~ та же заморозка
            res.stalled, res.stall_at = True, res.bytes_received
    finally:
        res.elapsed = round(time.perf_counter() - t0, 2)
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.5)
            except Exception:
                pass
    if res.error and not res.bytes_received:
        res.verdict, res.note = "error", res.error
    else:
        res.verdict, res.note = classify(res.bytes_received, res.completed, res.stalled)
    return res
