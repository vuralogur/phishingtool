"""Who is this mail really from? - alignment, brand-domain spoofing, sender domains.

The checks here answer one question from several directions: does anything
prove the From address, and does the sender's own domain pretend to be a brand.
Each attack is paired with the genuine mail that looks most like it.
"""
import pytest

from detector import analyzer, config, parser
from detector.checks import content, headers, url_deep, urls
from detector.scoring import SOFT_IDS
from detector.util import skeleton

CTX = analyzer.build_context(config=config.DEFAULTS)

RECEIVED = ("Received: from a.b.com (a.b.com [8.8.8.8]) by mx.victim.example with "
            "ESMTPS; Tue, 05 Aug 2025 09:00:01 +0000\r\n")

# Real-world shapes of the header (Gmail, Microsoft 365).
GMAIL_PAYPAL = (
    "mx.google.com; dkim=pass header.i=@paypal.com header.s=pp1 header.b=abc; "
    "spf=pass (google.com: domain of service@paypal.com designates 1.2.3.4 as "
    "permitted sender) smtp.mailfrom=service@paypal.com; "
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com")
O365_MICROSOFT = (
    "spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=email.microsoft.com; "
    "dkim=pass (signature was verified) header.d=microsoft.com;"
    "dmarc=pass action=none header.from=microsoft.com;compauth=pass reason=100")


def _mail(frm, auth=None, body="Merhaba, bilginize.", received=True, reply_to=None,
          html=None):
    raw = (RECEIVED if received else "")
    if auth:
        raw += "Authentication-Results: " + auth + "\r\n"
    raw += "From: " + frm + "\r\nTo: user@victim.example\r\nSubject: Bilgilendirme\r\n"
    if reply_to:
        raw += "Reply-To: " + reply_to + "\r\n"
    raw += "Content-Type: text/" + ("html" if html else "plain") + "; charset=utf-8\r\n\r\n"
    raw += (html or body) + "\r\n"
    return parser.parse_bytes(raw.encode("utf-8"))


def _analyze(email):
    r = analyzer.analyze(email, ctx=CTX)
    return r, {i.id: i for i in r.indicators}


# ---------------------------------------------------------------------------
# alignment(): whose domain did the pass vouch for
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("frm, auth, state", [
    ("PayPal <service@paypal.com>", GMAIL_PAYPAL, "aligned"),
    ("Microsoft <no-reply@microsoft.com>", O365_MICROSOFT, "aligned"),
    # Receiver wrote no DMARC verdict, but DKIM signed for the From domain.
    ("Akbank <bilgi@akbank.com>",
     "mx; spf=pass smtp.mailfrom=bounce.esp-mailer.net; dkim=pass header.d=akbank.com",
     "aligned"),
    # Subdomain signer: relaxed alignment compares registrable domains.
    ("Shop <info@shop.example.com>", "mx; dkim=pass header.d=mail.example.com", "aligned"),
    ("PayPal <service@paypal.com>",
     "mx; spf=pass smtp.mailfrom=evil-mailer.com; dkim=pass header.d=evil-mailer.com",
     "unaligned"),
    # DMARC passed - for a From this mail does not show.
    ("PayPal <service@paypal.com>", "mx; dmarc=pass header.from=evil.tk", "unaligned"),
    # A pass that does not say for whom: cannot be judged either way.
    ("Shop <info@shop-ornek.com>", "mx; spf=pass; dkim=pass", "unknown"),
    ("Shop <info@shop-ornek.com>", "mx; dmarc=pass", "aligned"),
    ("PayPal <service@paypal.com>",
     "mx; spf=softfail smtp.mailfrom=paypal.com; dkim=none; dmarc=fail header.from=paypal.com",
     "nopass"),
    ("Shop <info@shop-ornek.com>", None, "none"),
    # A domain inside a comment is prose, not a property.
    ("PayPal <service@paypal.com>",
     "mx; spf=pass (header.d=paypal.com looks fine; dkim=pass) smtp.mailfrom=evil.tk",
     "unaligned"),
])
def test_alignment(frm, auth, state):
    assert headers.alignment(_mail(frm, auth))[0] == state


def test_unaligned_pass_buys_no_trust_discount():
    """The attacker's server passes SPF and DKIM - for the attacker's own domain."""
    email = _mail("Butik <info@butik-ornek.com>",
                  "mx; spf=pass smtp.mailfrom=mcsv.net; dkim=pass header.d=mcsv.net",
                  body="ACILEN hemen dogrulayin, hesabiniz askiya alinacak.")
    r, ids = _analyze(email)
    assert r.breakdown.auth_level == "none" and r.breakdown.multiplier == 1.0
    note = ids["auth_pass_unaligned"]
    assert "mcsv.net" in note.evidence and "butik-ornek.com" in note.evidence
    assert note.id in SOFT_IDS and note.technique == ""
    assert r.verdict == "low"          # an ESP's default signature is not an attack


def test_aligned_and_unknown_passes_keep_their_level():
    email = _mail("Akbank <bilgi@akbank.com>",
                  "mx; spf=pass smtp.mailfrom=esp-mailer.net; dkim=pass header.d=akbank.com")
    r, ids = _analyze(email)
    assert r.breakdown.auth_level == "partial" and "auth_pass_unaligned" not in ids

    r, ids = _analyze(_mail("Shop <info@shop-ornek.com>", "mx; spf=pass"))
    assert r.breakdown.auth_level == "partial" and "auth_pass_unaligned" not in ids


def test_dmarc_pass_for_another_from_is_not_a_pass():
    email = _mail("Shop <info@shop-ornek.com>", "mx; dmarc=pass header.from=baska.example.net")
    r, ids = _analyze(email)
    assert r.breakdown.auth_level == "none" and "auth_pass_unaligned" in ids


# ---------------------------------------------------------------------------
# brand_domain_spoof: the brand's real domain in From, nothing proving it
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("frm, auth", [
    ("PayPal <service@paypal.com>", GMAIL_PAYPAL),
    ("Microsoft <no-reply@microsoft.com>", O365_MICROSOFT),
    ("Akbank <bilgi@akbank.com>",
     "mx; spf=pass smtp.mailfrom=esp-mailer.net; dkim=pass header.d=akbank.com"),
    # Microsoft's verdict for a domain without a DMARC record.
    ("Garanti <bilgi@garantibbva.com.tr>",
     "spf=pass smtp.mailfrom=garantibbva.com.tr; dkim=none;dmarc=bestguesspass "
     "action=none header.from=garantibbva.com.tr"),
    ("GitHub <noreply@github.com>", "mx; spf=pass; dkim=pass; dmarc=pass"),
])
def test_genuine_brand_mail_is_clean(frm, auth):
    r, ids = _analyze(_mail(frm, auth))
    assert not ids and r.verdict == "low"


def test_exact_brand_domain_with_only_foreign_passes_is_a_spoof():
    email = _mail("PayPal <service@paypal.com>",
                  "mx; spf=pass smtp.mailfrom=bounce.evil-mailer.com; "
                  "dkim=pass header.d=evil-mailer.com")
    r, ids = _analyze(email)
    spoof = ids["brand_domain_spoof"]
    assert spoof.weight == 18 and spoof.technique == "T1656"
    assert "paypal" in spoof.evidence and "service@paypal.com" in spoof.evidence
    assert spoof.id not in SOFT_IDS
    assert r.verdict == "medium"


def test_brand_domain_failing_dmarc_is_high():
    email = _mail("PayPal <service@paypal.com>",
                  "mx; spf=softfail smtp.mailfrom=paypal.com; dkim=none; "
                  "dmarc=fail (p=REJECT) header.from=paypal.com")
    r, ids = _analyze(email)
    assert {"brand_domain_spoof", "dmarc_fail"} <= set(ids)
    assert r.verdict == "high"


def test_brand_domain_with_a_self_written_pass_is_a_spoof():
    """dmarc=pass and no Received line: nobody stamped that header."""
    r, ids = _analyze(_mail("PayPal <service@paypal.com>", GMAIL_PAYPAL, received=False))
    assert "brand_domain_spoof" in ids and "damgalayan sunucu yok" in ids["brand_domain_spoof"].evidence
    assert r.breakdown.auth_level == "none"


def test_brand_domain_without_any_verdict_is_only_a_note():
    r, ids = _analyze(_mail("Akbank <bilgi@akbank.com>"))
    assert "brand_domain_spoof" not in ids
    note = ids["brand_domain_unverified"]
    assert note.id in SOFT_IDS and note.technique == "" and "--online" in note.explanation
    assert r.verdict == "low"


def test_pass_without_properties_is_given_the_benefit_of_the_doubt():
    _, ids = _analyze(_mail("Akbank <bilgi@akbank.com>", "mx; spf=pass; dkim=pass"))
    assert "brand_domain_spoof" not in ids and "brand_domain_unverified" not in ids


def test_free_mailbox_domains_are_not_brand_spoofs():
    """gmail.com is in the brand list, but a person's mail failing auth through
    a mailing list is not somebody impersonating Google."""
    email = _mail("Ahmet <ahmet@gmail.com>",
                  "mx; spf=fail smtp.mailfrom=gmail.com; dkim=fail header.d=gmail.com; "
                  "dmarc=fail header.from=gmail.com")
    _, ids = _analyze(email)
    assert "brand_domain_spoof" not in ids


def test_ordinary_domains_are_never_brand_spoofs():
    _, ids = _analyze(_mail("Shop <info@shop-ornek.com>", "mx; spf=fail; dmarc=fail"))
    assert "brand_domain_spoof" not in ids and "brand_domain_unverified" not in ids


def test_msg_without_transport_headers_is_not_called_a_spoof():
    email = _mail("PayPal <service@paypal.com>")
    email.header_source = "mapi"
    ids = {i.id for i in headers.run(email, ctx=CTX)}
    assert "brand_domain_spoof" not in ids and "brand_domain_unverified" not in ids


def test_brand_check_needs_the_brand_dictionary():
    email = _mail("PayPal <service@paypal.com>", "mx; dmarc=fail")
    assert "brand_domain_spoof" not in {i.id for i in headers.run(email)}


# ---------------------------------------------------------------------------
# The sender's own domain meets the URL checks
# ---------------------------------------------------------------------------

def test_lookalike_sender_domain_without_any_link():
    r, ids = _analyze(_mail("Security Team <noreply@paypa1.com>"))
    found = ids["lookalike_domain"]
    assert found.evidence.startswith("Gonderen (From) domaini - ") and "paypal.com" in found.evidence
    assert r.verdict == "medium"


@pytest.mark.parametrize("frm, want", [
    ("Guvenlik <bilgi@akbank-giris.com>", "combosquat_domain"),
    ("Destek <no-reply@paypal.com.hesap-merkezi.net>", "brand_in_subdomain"),
    ("Bilgi <info@xn--pypal-4ve.com>", "confusable_brand"),      # Cyrillic а
])
def test_sender_domain_dressed_as_a_brand(frm, want):
    found = [i for i in url_deep.run(_mail(frm), ctx=CTX) if i.id == want]
    assert found and found[0].evidence.startswith("Gonderen (From) domaini: ")


def test_reply_to_domain_is_checked_too():
    email = _mail("Muhasebe <muhasebe@firma-ornek.com>", reply_to="odeme@paypa1.com")
    found = [i for i in urls.run(email, ctx=CTX) if i.id == "lookalike_domain"]
    assert found and found[0].evidence.startswith("Reply-To domaini - ")


def test_sender_and_link_on_the_same_domain_is_one_finding():
    email = _mail("Security <noreply@paypa1.com>",
                  html="<a href='https://paypa1.com/login'>Giris</a>")
    found = [i for i in urls.run(email, ctx=CTX) if i.id == "lookalike_domain"]
    assert len(found) == 1 and not found[0].evidence.startswith("Gonderen")


def test_sender_on_a_suspicious_tld_is_soft_context():
    email = _mail("Destek <destek@hesap-dogrulama.xyz>")
    found = [i for i in urls.run(email, ctx=CTX) if i.id == "suspicious_tld"]
    assert found and found[0].id in SOFT_IDS


@pytest.mark.parametrize("frm", [
    "Haber <news@example-news.com>", "PayPal <service@paypal.com>",
    "Ahmet <ahmet@gmail.com>", "Magaza <bulten@magaza-ornek.com.tr>",
    "Bilgi <info@[192.168.1.1]>", "Bozuk <adres-yok>",
])
def test_ordinary_senders_raise_no_domain_finding(frm):
    email = _mail(frm)
    assert not urls.run(email, ctx=CTX) and not url_deep.run(email, ctx=CTX)


# ---------------------------------------------------------------------------
# tld_swap_domain: same name, another ending
# ---------------------------------------------------------------------------

def _link_ids(host):
    return {i.id for i in urls.run(_mail("Bilgi <info@firma-ornek.com>",
            html="<a href='https://" + host + "/x'>link</a>"), ctx=CTX)}


@pytest.mark.parametrize("host", [
    "akbank.net", "www.isbank.net", "paypal.xyz", "garantibbva.com", "netflix.org",
    "paypal.tk",            # a country ending, but one on the suspicious list
])
def test_brand_name_under_another_ending(host):
    assert "tld_swap_domain" in _link_ids(host)


@pytest.mark.parametrize("host", [
    "www.akbank.com", "www.paypal.com", "www.zoom.com",   # the real ones
    "www.amazon.co.uk", "www.vodafone.de", "paypal.me",   # regional / country endings
    "x.org", "ups.net", "fb.org",                         # names too short to mean anything
    "www.example.org",
])
def test_real_and_regional_domains_are_not_tld_swaps(host):
    assert "tld_swap_domain" not in _link_ids(host)


def test_tld_swap_is_soft_and_names_the_way_out():
    email = _mail("Bilgi <info@firma-ornek.com>", html="<a href='https://akbank.net/x'>l</a>")
    r, ids = _analyze(email)
    swap = ids["tld_swap_domain"]
    assert swap.id in SOFT_IDS and "akbank.com" in swap.evidence
    assert "brands.txt" in swap.explanation
    assert r.verdict == "low"


# ---------------------------------------------------------------------------
# Display names written to defeat a string comparison
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("PayPal", "paypal"),
    ("PаyPal", "paypal"),                  # Cyrillic а
    ("РаyРаl", "paypal"),   # Cyrillic Р and а, upper and lower
    ("Pay​Pal", "paypal"),                 # zero-width space
    ("Pay­Pal﻿", "paypal"),           # soft hyphen, BOM
    ("ＰａｙＰａｌ", "paypal"),            # fullwidth
    ("\U0001d40f\U0001d41a\U0001d432\U0001d40f\U0001d41a\U0001d425", "paypal"),  # math bold
    ("VAKIFBANK", "vakifbank"),
    ("İş Bankası", "is bankasi"),
    ("", ""),
])
def test_skeleton(raw, expected):
    assert skeleton(raw) == expected
    assert skeleton(None) == ""


@pytest.mark.parametrize("display", [
    "PаyPal Support", "Pay​Pal Support",
    "\U0001d40f\U0001d41a\U0001d432\U0001d40f\U0001d41a\U0001d425 Security",
    "Αkbank Guvenlik",                     # Greek Alpha
])
def test_disguised_brand_in_display_name_is_impersonation(display):
    email = parser.parse_bytes(
        (RECEIVED + "Subject: Bildirim\r\n\r\nMerhaba\r\n").encode())
    email.from_display, email.from_addr = display, "odeme.destek@gmail.com"
    email.from_domain = "gmail.com"
    found = [i for i in content.run(email, ctx=CTX) if i.id == "brand_impersonation"]
    assert found
    assert "benzer/görünmez karakterlerle" in found[0].evidence
    assert "gizlenmiş" in found[0].explanation
    assert found[0].evidence.isprintable()      # the raw name is shown escaped


def test_plainly_written_brand_keeps_the_plain_wording():
    r, ids = _analyze(_mail("PayPal Support <odeme.destek@gmail.com>"))
    assert "benzer/görünmez" not in ids["brand_impersonation"].evidence
    assert r.verdict == "medium"


def test_non_latin_display_names_are_not_brands():
    for display in ("Сбербанк Онлайн", "Ελληνική Τράπεζα", "Мария Иванова", "山田太郎"):
        email = parser.parse_bytes((RECEIVED + "Subject: x\r\n\r\nx\r\n").encode())
        email.from_display, email.from_addr = display, "info@ornek-firma.com"
        email.from_domain = "ornek-firma.com"
        assert "brand_impersonation" not in {i.id for i in content.run(email, ctx=CTX)}, display
