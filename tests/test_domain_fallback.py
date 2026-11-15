"""The core without tldextract: registrable domains under two-part suffixes.

The CI core job installs no optional dependency; a developer machine usually
has tldextract. So a domain bug that exists only in the fallback passes every
local run and fails on push - which is how "garantibbva.com.tr is a subdomain
of com.tr" reached main. These tests switch tldextract off themselves, so the
fallback is exercised wherever the suite runs.
"""
from email.message import EmailMessage

import pytest

from detector import analyzer, config, parser, util

PASS = ("mx.alici.com; spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; "
        "dmarc=pass header.from={d}")
RECEIVED = ("from mail.example.net ([93.184.216.34]) by mx.alici.com with ESMTPS; "
            "Mon, 2 Nov 2026 10:00:00 +0300")

CASES = [
    ("garantibbva.com.tr", "garantibbva.com.tr"),
    ("sube.garantibbva.com.tr", "garantibbva.com.tr"),
    ("www.turkiye.gov.tr", "turkiye.gov.tr"),
    ("ogrenci.itu.edu.tr", "itu.edu.tr"),
    ("x.y.belediye.bel.tr", "belediye.bel.tr"),
    ("shop.example.co.uk", "example.co.uk"),
    ("a.b.example.com.br", "example.com.br"),
    ("example.com.au", "example.com.au"),
    ("mail.example.co.jp", "example.co.jp"),
    # one-part suffixes are untouched
    ("login.paypal.com", "paypal.com"),
    ("paypal.com", "paypal.com"),
    ("a.b.c.example.org", "example.org"),
    ("kotu.pages.dev", "pages.dev"),
    ("nic.tr", "nic.tr"),
    ("sub.example.de", "example.de"),
    # a suffix on its own is not somebody's subdomain
    ("com.tr", "com.tr"),
    ("co.uk", "co.uk"),
    # not a country code: "com" before a long TLD is just a name
    ("a.com.online", "com.online"),
    ("192.168.1.1", "192.168.1.1"),
    ("localhost", "localhost"),
    ("", ""),
]


@pytest.fixture
def no_tldextract(monkeypatch):
    monkeypatch.setattr(util, "_extract", None)


@pytest.mark.parametrize("host, expected", CASES)
def test_fallback_registered_domain(no_tldextract, host, expected):
    assert util.registered_domain(host) == expected


@pytest.mark.parametrize("host, expected", [c for c in CASES if "." in c[0]
                                            and c[0] not in ("com.tr", "co.uk")])
def test_fallback_agrees_with_the_public_suffix_list(host, expected):
    if util._extract is None:
        pytest.skip("tldextract kurulu degil")
    assert util.registered_domain(host) == expected


def mail(frm, auth=None, html=None):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = "ali@alici.com"
    m["Subject"] = "Hesap ozeti"
    if auth:
        m["Authentication-Results"] = auth
    m["Received"] = RECEIVED
    m.set_content("Merhaba, hesap ozetiniz ektedir.")
    if html:
        m.add_alternative(html, subtype="html")
    return parser.parse_bytes(m.as_bytes())


def ids(email, ctx=None):
    ctx = ctx or analyzer.build_context(config=config.DEFAULTS)
    return {i.id for i in analyzer.analyze(email, ctx=ctx).indicators}


def test_genuine_com_tr_brand_mail_is_clean_without_tldextract(no_tldextract):
    # The mail CI went red on: a bank writing from its own .com.tr domain.
    found = ids(mail("Garanti <bilgi@garantibbva.com.tr>",
                     PASS.format(d="garantibbva.com.tr"),
                     '<a href="https://www.garantibbva.com.tr/kampanya">Kampanya</a>'))
    assert not found & {"brand_in_subdomain", "brand_impersonation",
                        "lookalike_domain", "brand_domain_spoof", "combosquat_domain"}


def test_two_com_tr_domains_are_not_the_same_sender(no_tldextract):
    # With "com.tr" as everybody's registrable domain, a link to any other
    # .com.tr site counted as first-party and the mismatch was suppressed.
    found = ids(mail("Kargo <bilgi@ornek-kargo.com.tr>", None,
                     '<a href="https://baska-site.com.tr/giris">www.ornek-kargo.com.tr</a>'))
    assert "anchor_href_mismatch" in found


def test_own_com_tr_domain_is_protected_without_tldextract(no_tldextract, tmp_path):
    for name in ("brands.txt", "suspicious_tlds.txt", "urgency_keywords.txt",
                 "trusted_domains.txt", "vip_names.txt"):
        (tmp_path / name).write_text("", encoding="utf-8")
    (tmp_path / "own_domains.txt").write_text("sirketim.com.tr\n", encoding="utf-8")
    ctx = analyzer.build_context(tmp_path, config.DEFAULTS)
    # our own domain, properly authenticated: nothing to say
    assert not ids(mail("IK <ik@sirketim.com.tr>", PASS.format(d="sirketim.com.tr")), ctx) \
        & {"brand_in_subdomain", "brand_domain_spoof", "lookalike_domain"}
    # a look-alike of it is still caught
    assert "lookalike_domain" in ids(mail("IK <ik@sirketlm.com.tr>"), ctx)
