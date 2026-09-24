"""
Разбор сертификата target-а.

При verify_mode=CERT_NONE ssl.getpeercert() возвращает пустой dict —
в v3 из-за этого subject/issuer/срок никогда не заполнялись. Парсим DER.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class CertInfo:
    subject_cn: str = ""
    issuer_org: str = ""
    issuer_cn: str = ""
    names: List[str] = field(default_factory=list)
    days_left: int = 0
    self_signed: bool = False


def _attr(name: x509.Name, oid) -> str:
    vals = name.get_attributes_for_oid(oid)
    return str(vals[0].value) if vals else ""


def parse_der(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    info = CertInfo(
        subject_cn=_attr(cert.subject, NameOID.COMMON_NAME),
        issuer_org=_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        issuer_cn=_attr(cert.issuer, NameOID.COMMON_NAME),
        self_signed=cert.subject == cert.issuer,
    )
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        info.names = [n.lower() for n in san.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass
    if info.subject_cn and info.subject_cn.lower() not in info.names:
        info.names.append(info.subject_cn.lower())
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    info.days_left = (not_after - datetime.now(timezone.utc)).days
    return info


def name_matches(host: str, names: List[str]) -> bool:
    """RFC 6125: wildcard покрывает ровно одну метку слева."""
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == n[2:]:
                return True
    return False


def concrete_names(names: List[str]) -> List[str]:
    """Имена без wildcard — кандидаты в SNI при сканировании подсети."""
    return [n for n in names if "*" not in n and "." in n]


# Выпускающие CA, характерные для MITM (РФ/КЗ/корпоративные прокси)
MITM_ISSUERS = [
    "russian trusted", "минцифры", "rostelecom", "rostelekom", "mgts",
    "rkn", "minsvyaz",
    "trustwave", "bluecoat", "squid", "fortinet", "fortigate", "paloalto",
    "checkpoint", "zscaler", "netskope", "websense", "barracuda", "untangle",
    "qaznet", "national security", "cnnic",
]


def is_mitm_issuer(info: CertInfo) -> bool:
    text = f"{info.issuer_org} {info.issuer_cn}".lower()
    return any(kw in text for kw in MITM_ISSUERS)
