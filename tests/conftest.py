import asyncio
import datetime
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert(tmp_path, cn="test.local", sans=("test.local", "www.test.local")):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(s) for s in sans]), critical=False)
            .sign(key, hashes.SHA256()))
    cp, kp = tmp_path / "cert.pem", tmp_path / "key.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return cert, str(cp), str(kp)


class TLSServer:
    """Локальный TLS 1.3 сервер в отдельном потоке.

    handler(reader, writer) — корутина, обслуживающая соединение.
    """

    def __init__(self, certfile, keyfile, handler, alpn=("h2", "http/1.1")):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile, keyfile)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if alpn:
            self.ctx.set_alpn_protocols(list(alpn))
        self.handler = handler
        self.loop = asyncio.new_event_loop()
        self.port = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        asyncio.set_event_loop(self.loop)

        async def start():
            srv = await asyncio.start_server(self.handler, "127.0.0.1", 0, ssl=self.ctx)
            self.port = srv.sockets[0].getsockname()[1]
            self.server = srv
            self._ready.set()
        self.loop.run_until_complete(start())
        self.loop.run_forever()

    def __enter__(self):
        self._thread.start()
        self._ready.wait(5)
        return self

    def __exit__(self, *exc):
        async def shutdown():
            self.server.close()
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(3)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(2)


async def http_ok_handler(reader, writer, body=b"x" * 1000, status=b"200 OK", extra=b""):
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
        writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\n" + extra + b"Connection: close\r\n\r\n" + body)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


@pytest.fixture
def cert_files(tmp_path):
    return make_cert(tmp_path)
