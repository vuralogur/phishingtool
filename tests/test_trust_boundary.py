"""Where the tool decides whom to believe, and where it stops guessing.

Three families of regression, each one a bug that shipped:

* **Trust boundary** - the score is allowed to trust the LAST server that
  handled the mail and nothing below it. A message that carries its own
  "dmarc=pass" line used to be read as authenticated, which discounted every
  soft signal to 30% and cost a critical verdict.
* **Not-a-domain tokens** - "Kargo Ltd.Sti" and two-letter brand domains
  produced hard, verdict-driving indicators on ordinary mail.
* **Turkish case folding** - str.lower() maps "I" to "i" and never to "ı", so
  an ALL-CAPS Turkish subject line matched no keyword at all.
"""
from detector import analyzer, parser
from detector.checks import headers
from detector.util import ascii_fold, looks_like_domain, lookalike_distance

CTX = analyzer.build_context()

_PHISH_BODY = (b"From: PayPal Guvenlik <security@paypal-dogrulama.tk>\r\n"
               b"Subject: Hesabiniz askiya alindi\r\n"
               b"Content-Type: text/html\r\n\r\n"
               b'<a href="http://paypal-dogrulama.tk/login">paypal.com</a> '
               b"sifrenizi guncelleyin acilen\r\n")
_FORGED = b"Authentication-Results: made-up; spf=pass; dkim=pass; dmarc=pass\r\n"


def _mail(*header_lines):
    return parser.parse_bytes(b"".join(header_lines) + _PHISH_BODY)


# ---------- trust boundary ----------


def test_sender_supplied_auth_header_does_not_buy_trust():
    """The only A-R header is the sender's own: it must not authenticate them.

    The report still repeats what the header says - that is what the file
    contains - but nothing corroborates it, so the score refuses the discount
    and the whole difference between the two mails is one extra indicator.
    """
    forged = _mail(_FORGED)
    honest = _mail()
    assert headers.summary(forged)["dmarc"] == "pass"      # reported verbatim
    scored = analyzer.analyze(forged, ctx=CTX)
    assert scored.breakdown.auth_level == "none"           # but not believed
    assert scored.breakdown.multiplier == 1.0
    assert scored.verdict == analyzer.analyze(honest, ctx=CTX).verdict
    assert "auth_claim_unverifiable" in {i.id for i in scored.indicators}


def test_top_header_is_authoritative_and_lower_ones_cannot_top_it_up():
    """A genuine spf=fail on top, an invented dmarc=pass below - fail wins."""
    email = _mail(b"Authentication-Results: mx.kurum.com.tr; spf=fail smtp.mailfrom=x.tk\r\n",
                  b"Authentication-Results: made-up; dmarc=pass; dkim=pass\r\n")
    a = headers.summary(email)
    assert a["spf"] == "fail"
    # The top header says nothing about DMARC/DKIM, so neither does the report.
    assert a["dmarc"] == "none" and a["dkim"] == "none"
    assert analyzer.analyze(email, ctx=CTX).breakdown.auth_level == "fail"


def test_top_header_is_believed_when_it_authenticates():
    """The rule is "topmost wins", not "never trust anything"."""
    email = _mail(b"Authentication-Results: mx.kurum.com.tr; spf=pass; dkim=pass; dmarc=pass\r\n",
                  b"Authentication-Results: older-hop; spf=fail\r\n")
    assert headers.summary(email) == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_disagreement_is_reported_but_never_scored():
    from detector.scoring import SOFT_IDS
    email = _mail(b"Authentication-Results: mx.kurum.com.tr; spf=fail\r\n",
                  b"Authentication-Results: made-up; spf=pass; dmarc=pass\r\n")
    found = {i.id: i for i in headers.run(email, False, CTX)}
    assert "auth_results_conflict" in found
    conflict = found["auth_results_conflict"]
    assert "spf=pass" in conflict.evidence and "dmarc=pass" in conflict.evidence
    # Soft + unmapped: it explains the auth line, it does not drive the verdict.
    assert "auth_results_conflict" in SOFT_IDS
    assert conflict.technique == ""


def test_single_auth_header_raises_no_conflict():
    email = _mail(b"Authentication-Results: mx.kurum.com.tr; spf=fail\r\n")
    assert "auth_results_conflict" not in {i.id for i in headers.run(email, False, CTX)}


def test_received_spf_header_is_read_with_its_own_grammar():
    """Received-SPF says "Pass (...)", not "spf=pass" - it used to be dropped."""
    email = _mail(b"Received-SPF: Fail (mx.kurum.com.tr: domain of x.tk does not "
                  b"designate 45.9.1.2 as permitted sender)\r\n")
    assert headers.summary(email)["spf"] == "fail"
    assert "spf_fail" in {i.id for i in headers.run(email, False, CTX)}


def test_authentication_results_still_beats_received_spf():
    email = _mail(b"Authentication-Results: mx.kurum.com.tr; spf=fail\r\n",
                  b"Received-SPF: Pass (mx.kurum.com.tr: designated sender)\r\n")
    assert headers.summary(email)["spf"] == "fail"


# ---------- tokens that only look like domains ----------


def test_company_suffix_in_display_name_is_not_a_spoofed_domain():
    email = parser.parse_bytes(b'From: "Kargo Ltd.Sti" <bilgi@sirket.com.tr>\r\n'
                               b"Subject: Siparis bilgisi\r\n\r\nmerhaba\r\n")
    assert "display_name_spoof" not in {i.id for i in headers.run(email, False, CTX)}


def test_real_foreign_domain_in_display_name_still_spoofs():
    email = parser.parse_bytes(b'From: "paypal.com Guvenlik" <bilgi@sahte.tk>\r\n'
                               b"Subject: t\r\n\r\nmerhaba\r\n")
    assert "display_name_spoof" in {i.id for i in headers.run(email, False, CTX)}


def test_looks_like_domain_needs_a_public_suffix():
    assert looks_like_domain("paypal.com")
    assert looks_like_domain("www.garantibbva.com.tr")
    assert not looks_like_domain("ltd.sti")
    assert not looks_like_domain("bilgi")


def test_lookalike_allowance_scales_with_the_brand_name():
    # Two edits from "fb.com" is half the internet.
    assert lookalike_distance("vb.com", "fb.com") == 0
    assert lookalike_distance("gb.com", "fb.com") == 0
    # A long brand keeps its two-edit allowance.
    assert lookalike_distance("paypa1.com", "paypal.com") == 1
    assert lookalike_distance("garantibbwa.com.tr", "garantibbva.com.tr") == 1
    assert lookalike_distance("micros0ft.com", "microsoft.com") == 1
    assert lookalike_distance("paypal.com", "paypal.com") == 0


def test_short_brand_domain_no_longer_flags_unrelated_hosts():
    from detector.checks import urls
    email = parser.parse_bytes(b"From: a@sirket.com\r\nSubject: t\r\n\r\n"
                               b"https://vb.com/rapor\r\n")
    assert "lookalike_domain" not in {i.id for i in urls.run(email, False, CTX)}


# ---------- Turkish case folding ----------


def test_ascii_fold_bridges_the_dotless_i():
    assert ascii_fold("VAKIFBANK") == ascii_fold("vakıfbank") == "vakifbank"
    assert ascii_fold("ACİLEN") == ascii_fold("acilen") == "acilen"
    assert ascii_fold("ŞİFRENİZİ GÜNCELLEYİN") == "sifrenizi guncelleyin"


def test_all_caps_turkish_subject_still_matches_the_keyword_list():
    from detector.checks import content
    # Built as bytes with a declared charset, the way a real .eml carries
    # Turkish - an undeclared body is decoded as ASCII and loses the letters.
    email = parser.parse_bytes(
        "From: a@sahte.tk\r\nSubject: HESABINIZ ASKIYA ALINDI\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "LUTFEN ŞİFRENİZİ GÜNCELLEYİN\r\n".encode("utf-8"))
    ids = {i.id for i in content.run(email, False, CTX)}
    assert "urgency_language" in ids
    assert "credential_request" in ids


def test_brand_written_without_turkish_letters_still_impersonates():
    from detector.checks import content
    email = parser.parse_text('From: "VAKIFBANK Guvenlik" <destek@sahte-vakif.tk>\r\n'
                              "Subject: t\r\n\r\nmerhaba\r\n")
    assert "brand_impersonation" in {i.id for i in content.run(email, False, CTX)}
