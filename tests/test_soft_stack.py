"""The soft-stack rule: the one way soft signals reach "medium" by themselves.

Tested from both sides, like every precision/recall trade in this tool: the
stacks it exists for must move, and the bulk-mail noise it must not mistake for
one (urgent wording, tracker redirects, a lone shortener, a lone .docm) must
stay exactly where it was.
"""
from email.message import EmailMessage

import pytest

from detector import analyzer, config, parser, report
from detector.indicators import Indicator
from detector.scoring import SOFT_IDS, STACK_IDS, THRESHOLDS, score

NONE = {"spf": "none", "dkim": "none", "dmarc": "none"}
PARTIAL = {"spf": "pass", "dkim": "none", "dmarc": "none"}
PASS = {"spf": "pass", "dkim": "pass", "dmarc": "pass"}

CTX = analyzer.build_context(config=config.DEFAULTS)
RECEIVED = ("from mail.example.net ([93.184.216.34]) by mx.alici.com with ESMTPS; "
            "Mon, 2 Nov 2026 10:00:00 +0300")


def ind(id_, weight, category="url"):
    return Indicator(id_, category, "medium", weight, "e", "x")


def pair():
    return [ind("url_shortener", 8), ind("suspicious_tld", 8)]


def noise():
    """What a legitimate ESP newsletter trips by construction - 46 points."""
    return [ind("urgency_language", 12, "content"), ind("generic_greeting", 4, "content"),
            ind("open_redirect", 10), ind("random_host", 6),
            ind("excessive_subdomains", 6), ind("hidden_text", 8, "html")]


def mail(frm, subject, html=None, text="merhaba", return_path=None, auth=None,
         attachments=()):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = "ali@alici.com"
    m["Subject"] = subject
    if return_path:
        m["Return-Path"] = return_path
    if auth:
        m["Authentication-Results"] = auth
    m["Received"] = RECEIVED
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, ctype, data in attachments:
        main, sub = ctype.split("/")
        m.add_attachment(data, maintype=main, subtype=sub, filename=name)
    return parser.parse_bytes(m.as_bytes())


STACKED_PHISH = dict(
    frm="Destek <destek@hesap-islem.xyz>",
    subject="ACIL: hesabiniz askiya alinacak",
    html='<p>Sayin musteri, hesabiniz 24 saat icinde kapatilacak. Hemen '
         '<a href="https://bit.ly/3xYz">buraya</a> veya '
         '<a href="https://giris.guvenlik.dogrula.hesap-islem.xyz/a">buraya</a>'
         ' tiklayin.</p>',
)


# -- the registry ------------------------------------------------------------


def test_stack_ids_are_known_soft_indicators():
    assert STACK_IDS <= SOFT_IDS
    assert STACK_IDS <= config.KNOWN_IDS


@pytest.mark.parametrize("id_", [
    "urgency_language", "generic_greeting",                  # tone
    "open_redirect", "random_host", "excessive_subdomains",  # tracker plumbing
    "hidden_text", "archive_attachment", "pdf_embedded_file",
    "from_returnpath_mismatch", "brand_domain_unverified",   # auth notes
    "auth_pass_unaligned", "no_received_headers",
])
def test_bulk_mail_noise_is_not_a_carrier_signal(id_):
    assert id_ in SOFT_IDS and id_ not in STACK_IDS


# -- the rule ----------------------------------------------------------------


def test_two_carrier_signals_from_an_unknown_sender_are_medium():
    r = score(pair(), NONE)
    b = r.breakdown
    assert r.verdict == "medium" and b.reason == "soft_stack"
    assert b.hard == 0 and b.stack == 16
    assert b.stack_ids == ("url_shortener", "suspicious_tld")


def test_one_carrier_signal_is_an_anecdote():
    r = score([ind("url_shortener", 8)], NONE)
    assert r.verdict == "low" and r.breakdown.reason == "no_hard_evidence"


def test_noise_does_not_complete_a_stack():
    r = score(noise() + [ind("url_shortener", 8)], NONE)
    assert r.score == 54 and r.verdict == "low"


def test_noise_alone_stays_low_whatever_it_adds_up_to():
    r = score(noise(), NONE)
    assert r.score == 46 and r.verdict == "low"
    assert r.breakdown.stack == 0 and r.breakdown.stack_ids == ()


def test_the_same_signal_twice_is_one_signal():
    r = score([ind("url_shortener", 8), ind("url_shortener", 8)], NONE)
    assert r.verdict == "low"


def test_a_zero_weight_signal_does_not_count():
    r = score([ind("url_shortener", 0), ind("suspicious_tld", 20)], NONE)
    assert r.verdict == "low"


def test_the_stack_never_goes_past_medium():
    r = score([ind(i, 12) for i in sorted(STACK_IDS)], NONE)
    assert r.breakdown.hard == 0 and r.score == 100
    assert r.verdict == "medium"


# -- trust -------------------------------------------------------------------


def test_dmarc_authenticated_sender_is_outside_the_rule():
    r = score([ind(i, 12) for i in sorted(STACK_IDS)], PASS)
    assert r.verdict == "low" and r.breakdown.reason == "no_hard_evidence"


def test_half_trusted_sender_needs_a_taller_stack():
    assert score(pair(), PARTIAL).verdict == "low"        # 16 x 0.6 = 9.6
    tall = [ind("punycode_domain", 12), ind("meta_refresh_redirect", 12, "html"),
            ind("url_shortener", 8)]
    r = score(tall, PARTIAL)                              # 32 x 0.6 = 19.2
    assert r.verdict == "medium" and round(r.breakdown.stack, 1) == 19.2


# -- next to hard evidence ---------------------------------------------------


def test_weak_hard_evidence_on_top_of_a_stack_does_not_lower_the_verdict():
    weak = ind("credential_request", 6, "content")
    assert score([weak], NONE).verdict == "low"
    r = score(pair() + [weak], NONE)
    assert r.breakdown.hard == 6
    assert r.verdict == "medium" and r.breakdown.reason == "soft_stack"


def test_hard_evidence_still_decides_when_it_can():
    r = score(pair() + [ind("ip_url", 14)], NONE)
    assert r.verdict == "medium" and r.breakdown.reason == "hard_medium"
    assert r.breakdown.stack == 0 and r.breakdown.stack_ids == ()
    r = score(pair() + [ind("ip_url", 25)], NONE)
    assert r.verdict == "high"


# -- config ------------------------------------------------------------------


def test_defaults():
    assert THRESHOLDS["soft_stack_min"] == 2 and THRESHOLDS["soft_stack"] == 15
    assert config.DEFAULTS.thresholds["soft_stack"] == 15


def test_min_zero_switches_the_rule_off():
    cfg = config.from_dict({"thresholds": {"soft_stack_min": 0}})
    r = score(pair(), NONE, config=cfg)
    assert r.verdict == "low" and r.breakdown.reason == "no_hard_evidence"
    assert cfg.changed == ("thresholds",)


def test_thresholds_move_the_bar():
    three = config.from_dict({"thresholds": {"soft_stack_min": 3}})
    assert score(pair(), NONE, config=three).verdict == "low"
    assert score(pair() + [ind("punycode_domain", 12)], NONE,
                 config=three).verdict == "medium"
    points = config.from_dict({"thresholds": {"soft_stack": 20}})
    assert score(pair(), NONE, config=points).verdict == "low"


def test_a_weight_override_reaches_the_stack():
    cfg = config.from_dict({"weights": {"url_shortener": 0}})
    assert score(pair(), NONE, config=cfg).verdict == "low"


def test_promoting_a_carrier_signal_to_hard_does_not_lower_the_verdict():
    cfg = config.from_dict({"soft_ids": {"remove": ["url_shortener"]}})
    r = score(pair(), NONE, config=cfg)
    assert r.breakdown.hard == 8                 # counted as hard evidence...
    assert r.verdict == "medium"                 # ...and still part of the stack
    assert r.breakdown.reason == "soft_stack"


@pytest.mark.parametrize("raw", [
    {"thresholds": {"soft_stack": 101}},
    {"thresholds": {"soft_stack_min": -1}},
    {"thresholds": {"soft_stack_min": 1.5}},
    {"thresholds": {"soft_stacks": 10}},
])
def test_bad_values_are_loud(raw):
    with pytest.raises(config.ConfigError):
        config.from_dict(raw)


# -- the report says why -----------------------------------------------------


def test_report_names_the_signals_that_were_counted():
    lines = report.breakdown_lines(score(pair(), NONE))
    assert "url_shortener, suspicious_tld = 16 puan" in lines[1]
    assert "→ medium" in lines[1]


def test_json_breakdown_carries_the_stack():
    b = score(pair(), NONE).to_dict()["breakdown"]
    assert b["reason"] == "soft_stack"
    assert b["stack"] == 16 and b["stack_ids"] == ["url_shortener", "suspicious_tld"]
    quiet = score([ind("url_shortener", 8)], NONE).to_dict()["breakdown"]
    assert quiet["stack"] == 0 and quiet["stack_ids"] == []


# -- end to end: the mails the rule is for -----------------------------------


def test_unauthenticated_shortener_plus_throwaway_tld_mail_is_medium():
    r = analyzer.analyze(mail(**STACKED_PHISH), ctx=CTX)
    assert r.breakdown.hard == 0
    assert {"url_shortener", "suspicious_tld"} <= set(r.breakdown.stack_ids)
    assert r.verdict == "medium" and r.breakdown.reason == "soft_stack"


def test_macro_document_from_a_throwaway_tld_is_medium():
    r = analyzer.analyze(mail(
        "Muhasebe <muhasebe@firma-odeme.click>", "Odenmemis fatura",
        text="Sayin yetkili, ekteki faturayi bugun odeyiniz.",
        attachments=[("fatura.docm",
                      "application/vnd.ms-word.document.macroEnabled.12",
                      b"PK\x03\x04xx")]), ctx=CTX)
    assert set(r.breakdown.stack_ids) == {"macro_document", "suspicious_tld"}
    assert r.verdict == "medium"


def test_the_same_mail_with_dmarc_pass_stays_low():
    r = analyzer.analyze(mail(
        auth="mx.alici.com; spf=pass smtp.mailfrom=hesap-islem.xyz; "
             "dkim=pass header.d=hesap-islem.xyz; "
             "dmarc=pass header.from=hesap-islem.xyz",
        **STACKED_PHISH), ctx=CTX)
    assert r.breakdown.auth_level == "pass" and r.verdict == "low"


# -- end to end: the mails it must leave alone -------------------------------


def test_esp_newsletter_without_auth_results_stays_low():
    r = analyzer.analyze(mail(
        "Moda Magaza <bulten@modamagaza.com.tr>", "Son gun! Sezon indirimi bitiyor",
        html='<div style="display:none;max-height:0">Sezon sonu firsatlari</div>'
             '<p>Degerli musterimiz, kampanya bu gece bitiyor, kacirmayin!</p>'
             '<a href="https://u1234567.ct.sendgrid.net/ls/click?upn=abc&url='
             'https%3A%2F%2Fmodamagaza.com.tr%2Fs">Alisverise basla</a>'
             '<a href="https://x7k2m9qp4z.r.eu-west-1.awstrack.me/L0/'
             'https:%2F%2Fmodamagaza.com.tr/1/abc">Urunler</a>',
        return_path="bounce-123@sendgrid.net"), ctx=CTX)
    assert r.breakdown.soft_count >= 3           # it is noisy...
    assert r.verdict == "low"                    # ...and that is all it is


def test_invoice_with_one_shortener_link_stays_low():
    r = analyzer.analyze(mail(
        "Muhasebe <fatura@tedarikci.com.tr>", "Kasim ayi faturaniz",
        html='<p>Sayin musterimiz, faturaniz ektedir. Odeme icin: '
             '<a href="https://bit.ly/odeme">link</a></p>',
        attachments=[("fatura.pdf", "application/pdf", b"%PDF-1.4\n%%EOF")]),
        ctx=CTX)
    assert "url_shortener" in {i.id for i in r.indicators}
    assert r.verdict == "low"


def test_internal_macro_spreadsheet_stays_low():
    r = analyzer.analyze(mail(
        "Finans <finans@sirketim.com.tr>", "Acil: butce tablosu",
        text="Merhaba, makrolu tabloyu acilen doldurup gonderin.",
        attachments=[("butce.docm",
                      "application/vnd.ms-word.document.macroEnabled.12",
                      b"PK\x03\x04xx")]), ctx=CTX)
    assert "macro_document" in {i.id for i in r.indicators}
    assert r.verdict == "low"
