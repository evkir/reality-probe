from cryptography.hazmat.primitives import serialization

from realityprobe.certs import (CertInfo, concrete_names, is_mitm_issuer,
                                name_matches, parse_der)
from conftest import make_cert


def test_parse_der(tmp_path):
    cert, _, _ = make_cert(tmp_path, cn="a.example.org", sans=("a.example.org", "*.cdn.example.org"))
    info = parse_der(cert.public_bytes(serialization.Encoding.DER))
    assert info.subject_cn == "a.example.org"
    assert info.issuer_org == "Test Org"
    assert "*.cdn.example.org" in info.names
    assert 88 <= info.days_left <= 90
    assert info.self_signed


def test_name_matches_wildcard_one_label():
    names = ["*.example.org", "example.org"]
    assert name_matches("www.example.org", names)
    assert name_matches("example.org", names)
    assert not name_matches("a.b.example.org", names)
    assert not name_matches("evil.org", names)


def test_concrete_names_and_mitm():
    assert concrete_names(["*.x.com", "x.com", "localhost"]) == ["x.com"]
    assert is_mitm_issuer(CertInfo(issuer_cn="Russian Trusted Sub CA"))
    assert not is_mitm_issuer(CertInfo(issuer_org="Let's Encrypt", issuer_cn="R11"))
