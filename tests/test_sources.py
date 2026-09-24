from realityprobe import policy
from realityprobe.sources import (BUILTIN_DOMAINS, WHITELIST_DOMAINS,
                                  DomainFetcher, domain_state)


def test_builtin_clean():
    assert BUILTIN_DOMAINS and len(BUILTIN_DOMAINS) == len(set(BUILTIN_DOMAINS))
    assert not any(policy.is_overused(d) or policy.is_excluded(d) for d in BUILTIN_DOMAINS)
    assert domain_state["total"] == len(BUILTIN_DOMAINS)


def test_whitelist_domains_whitelisted():
    assert all(policy.is_ru_whitelisted(d) for d in WHITELIST_DOMAINS)


def test_parse_domain_lines_formats():
    raw = "# c\nfull:cdn.example.com\nregexp:.*\n  - DOMAIN-SUFFIX,static.example.net,PROXY\nplain.example.org # x\n"
    assert DomainFetcher._parse_domain_lines(raw) == [
        "cdn.example.com", "static.example.net", "plain.example.org"]
