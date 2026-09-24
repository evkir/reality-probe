from realityprobe.scoring import (PROFILE_WHITELIST, Signals, evaluate,
                                  status_for)


def good(**kw):
    base = dict(tls_version="TLSv1.3", h2=True, mlkem=True, preferred_group="X25519MLKEM768",
                cert_matches=True, http_status=200, rtt_avg=30, server_known=True)
    base.update(kw)
    return Signals(**base)


def test_same_prefix_is_ideal_low_risk():
    v = evaluate(good(topology="same_prefix"))
    assert v.score == 95 and v.risk == "low" and v.suitable
    assert status_for(v.score) == "ideal"


def test_without_server_ip_caps_below_ideal():
    v = evaluate(good(server_known=False))
    assert v.score == 70 and v.risk == "medium"
    assert status_for(v.score) == "excellent"
    assert any("IP сервера" in n for n in v.notes)


def test_big_brand_on_hoster_ip_is_high_risk():
    v = evaluate(good(topology="foreign", donor_brand="Apple"))
    assert v.risk == "high" and v.score == 55
    assert any("Apple" in n for n in v.notes)


def test_overused_and_cloudflare_penalties():
    v = evaluate(good(overused=True, donor_cloudflare=True))
    assert v.risk == "high" and v.score == 40 and not v.suitable


def test_offsite_redirect_unsuitable():
    v = evaluate(good(topology="same_asn", redirect_offsite=True, http_status=301))
    assert not v.suitable and v.risk == "high"


def test_tls12_and_fatal():
    assert not evaluate(good(tls_version="TLSv1.2", topology="same_prefix")).suitable
    assert evaluate(good(fatal=True)).score == 0
    assert evaluate(Signals()).score == 0


def test_mlkem_missing_is_medium():
    v = evaluate(good(topology="same_prefix", mlkem=False, preferred_group="X25519"))
    assert v.risk == "medium" and v.score == 85


def test_whitelist_profile():
    assert not evaluate(good(topology="same_prefix", profile=PROFILE_WHITELIST)).suitable
    v = evaluate(good(topology="foreign", profile=PROFILE_WHITELIST, ru_whitelisted=True))
    assert v.suitable and v.score == 85


def test_cert_mismatch_unsuitable():
    v = evaluate(good(topology="same_prefix", cert_matches=False))
    assert not v.suitable and v.risk == "high"
