from realityprobe import policy
from realityprobe.filters import (is_infra_domain, is_suitable_for_scan, parse_ip,
                                  sanitize_domain, sanitize_ip)


def test_excluded_blocked_services():
    assert policy.is_excluded("www.instagram.com")
    assert policy.is_excluded("rr1.googlevideo.com")
    assert not policy.is_excluded("vk.com")          # в белом списке, не исключать
    assert not policy.is_excluded("ok.ru")


def test_overused_sni():
    assert policy.is_overused("www.microsoft.com")
    assert policy.is_overused("WWW.LOVELIVE-ANIME.JP.")
    assert not policy.is_overused("www.hetzner.com")


def test_ru_whitelist_suffix_match():
    assert policy.is_ru_whitelisted("ya.ru")
    assert policy.is_ru_whitelisted("static.gosuslugi.ru")
    assert not policy.is_ru_whitelisted("notya.ru")
    assert not policy.is_ru_whitelisted("example.com")


def test_cloudflare_ranges():
    assert policy.is_cloudflare_ip("104.16.1.1")
    assert policy.is_cloudflare_ip("172.67.0.1")
    assert policy.is_cloudflare_ip("2606:4700::1")
    assert not policy.is_cloudflare_ip("95.216.1.1")
    assert not policy.is_cloudflare_ip("garbage")


def test_asn_tables():
    assert policy.big_brand(13335) == "Cloudflare"
    assert policy.datacenter(24940) == "Hetzner"
    assert policy.big_brand(None) is None


def test_filters():
    assert is_infra_domain("e122475.dscg.akamaiedge.net")
    assert not is_suitable_for_scan("facebook.com")
    assert is_suitable_for_scan("www.hetzner.com")
    assert sanitize_domain("https://Example.com:443/path") == "example.com"
    assert sanitize_domain("bad domain") == ""
    assert sanitize_ip("1.2.3.4") == "1.2.3.4"
    assert sanitize_ip("999.1.1.1") == "<SERVER_IP>"
    assert sanitize_ip("vps.example.com") == "vps.example.com"
    assert sanitize_ip("2a01:4f8::1") == "2a01:4f8::1"
    assert parse_ip(" 95.216.1.1 ") == "95.216.1.1"
    assert parse_ip("example.com") == ""
