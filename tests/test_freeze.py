import asyncio

import pytest

from realityprobe.freeze import classify, freeze_test
from conftest import TLSServer


def _sender(total, hang):
    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
            writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            sent = 0
            while sent < total:
                n = min(2048, total - sent)
                writer.write(b"a" * n)
                await writer.drain()
                sent += n
            if hang:
                await asyncio.sleep(10)
        except Exception:
            pass
        finally:
            writer.close()
    return handler


@pytest.mark.parametrize("total,hang,verdict", [
    (18 * 1024, True, "frozen"),
    (60 * 1024, False, "clean"),
    (4 * 1024, False, "inconclusive"),
    (4 * 1024, True, "inconclusive"),
])
def test_freeze_verdicts(cert_files, total, hang, verdict):
    _, cp, kp = cert_files
    with TLSServer(cp, kp, _sender(total, hang), alpn=("http/1.1",)) as srv:
        res = asyncio.run(freeze_test("127.0.0.1", "test.local", port=srv.port,
                                      stall_timeout=1.0, total_timeout=8))
    assert res.verdict == verdict, res


def test_freeze_error_on_closed_port():
    res = asyncio.run(freeze_test("127.0.0.1", "x.test", port=1, stall_timeout=1))
    assert res.verdict == "error"


def test_classify_window_edges():
    assert classify(12 * 1024, False, True)[0] == "frozen"
    assert classify(24 * 1024, False, True)[0] == "frozen"
    assert classify(25 * 1024, False, True)[0] == "inconclusive"
    assert classify(30 * 1024, True, False)[0] == "clean"
