import asyncio
import struct

from realityprobe import tlshello as th
from conftest import TLSServer, http_ok_handler


def _server_hello(group, version=0x0304, random=b"\x11" * 32, cipher=0x1301):
    exts = struct.pack("!HHH", 0x002B, 2, version)
    exts += struct.pack("!HHH", 0x0033, 2 + 2 + 32, group) + struct.pack("!H", 32) + b"\x00" * 32
    body = (b"\x03\x03" + random + b"\x20" + b"\x00" * 32
            + struct.pack("!H", cipher) + b"\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def test_mlkem_encap_key_coefficients_below_q():
    ek = th.mlkem768_encap_key()
    assert len(ek) == 1184
    polys = ek[:1152]
    for i in range(0, len(polys), 3):
        b0, b1, b2 = polys[i:i + 3]
        assert (b0 | ((b1 & 0x0F) << 8)) < 3329
        assert ((b1 >> 4) | (b2 << 4)) < 3329


def test_client_hello_structure():
    ch = th.build_client_hello("example.com", [th.GROUP_X25519MLKEM768, th.GROUP_X25519],
                               [th.GROUP_X25519MLKEM768, th.GROUP_X25519])
    assert ch[0] == 0x16 and ch[5] == 0x01
    assert struct.unpack("!H", ch[3:5])[0] == len(ch) - 5
    assert b"example.com" in ch
    assert len(ch) > 1216                           # MLKEM share влез


def test_parse_server_hello_tls13_mlkem():
    info = th.parse_server_hello(_server_hello(th.GROUP_X25519MLKEM768))
    assert info.ok and info.version == "TLSv1.3" and info.group_name == "X25519MLKEM768"
    assert info.cipher == "TLS_AES_128_GCM_SHA256" and not info.hrr


def test_parse_hrr_and_alert():
    assert th.parse_server_hello(_server_hello(th.GROUP_X25519, random=th.HRR_RANDOM)).hrr
    alert = th.parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x28")
    assert not alert.ok and alert.alert == 40
    assert not th.parse_server_hello(b"\x16\x03").ok
    assert not th.parse_server_hello(b"\x16\x03\x03\x00\x04\x02\x00\x00\x01").ok


def test_kex_report_against_real_openssl(cert_files):
    _, cp, kp = cert_files
    with TLSServer(cp, kp, http_ok_handler) as srv:
        rep = asyncio.run(th.kex_report("127.0.0.1", srv.port, "test.local"))
    # OpenSSL 3.0 не знает MLKEM → выберет X25519, MLKEM-only получит отказ
    assert rep.error == ""
    assert rep.version == "TLSv1.3"
    assert rep.preferred in ("X25519", "X25519MLKEM768")
    assert rep.mlkem is (rep.preferred == "X25519MLKEM768")


def test_hello_probe_refused():
    info = asyncio.run(th.hello_probe("127.0.0.1", 1, "x.test", [th.GROUP_X25519],
                                      [th.GROUP_X25519], timeout=1))
    assert not info.ok and info.error
