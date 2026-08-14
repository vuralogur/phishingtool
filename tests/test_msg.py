"""Outlook .msg support: container reading, header fidelity, honest gaps."""
from datetime import datetime, timezone

import pytest

import msg_builder as B
from detector import analyzer, cli, mitre, msg, parser
from detector.scoring import SOFT_IDS

TRANSPORT = (
    "Received: from mx.contoso.tk (mx.contoso.tk [203.0.113.9])"
    " by mail.example.com; Fri, 14 Aug 2026 10:30:00 +0000\r\n"
    "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\r\n"
    "From: \"PayPal\" <alerts@paypa1-secure.tk>\r\n"
    "To: ali@example.com\r\n"
    "Reply-To: destek@baska-domain.tk\r\n"
    "Subject: Hesap dogrulama\r\n"
    "Date: Fri, 14 Aug 2026 10:30:00 +0000\r\n"
)


def phish_msg(**kw):
    """A .msg whose headers Outlook did NOT save (the MAPI-only case)."""
    defaults = dict(
        subject="Hesap dogrulama",
        body="Sifrenizi hemen dogrulayin: http://paypa1-secure.tk/login",
        html='<a href="http://guvenli-giris.tk/oturum">paypal.com</a>',
        sender=("PayPal Guvenlik", "noreply@contoso-mail.tk"),
        repr_sender=("PayPal Guvenlik", "alerts@paypa1-secure.tk"),
        recipients=[("Ali", "ali@example.com", 1), ("Veli", "veli@example.com", 2)],
        when=datetime(2026, 8, 14, 10, 30, tzinfo=timezone.utc),
    )
    defaults.update(kw)
    return B.message(**defaults)


# -- container ------------------------------------------------------------


def test_is_msg_only_matches_the_ole_signature():
    assert msg.is_msg(phish_msg())
    assert not msg.is_msg(b"From: a@b.com\r\nSubject: x\r\n\r\nhi")


def test_eml_path_is_untouched():
    email = parser.parse_bytes(b"From: a@example.com\r\nSubject: x\r\n\r\nhi")
    assert (email.source_format, email.header_source) == ("eml", "rfc822")


def test_truncated_container_raises_a_named_error():
    with pytest.raises(msg.MsgError):
        parser.parse_bytes(msg.SIGNATURE + b"\x00" * 40)


def test_big_and_mini_streams_both_round_trip():
    """Attachments >4096 bytes use their own sector chain, small props the mini stream."""
    blob = b"MZ" + b"A" * 6000
    email = parser.parse_bytes(phish_msg(
        attachments=[("fatura.pdf.exe", "application/octet-stream", blob)]))
    (att,) = email.attachments
    assert att.filename == "fatura.pdf.exe"
    assert att.payload == blob          # byte-exact: deep checks hash this
    assert att.size == len(blob)
    assert email.subject == "Hesap dogrulama"   # a mini-stream property


def test_codepage_property_decodes_8bit_body():
    raw = B.message(subject="Test", body="Şifrenizi doğrulayın", ansi_body=True,
                    codepage=1254, sender=("Ali", "ali@example.com"))
    assert "Şifrenizi doğrulayın" in parser.parse_bytes(raw).text_body


# -- header fidelity: saved internet headers ------------------------------


def test_saved_transport_headers_are_used_verbatim():
    email = parser.parse_bytes(B.message(
        transport=TRANSPORT, subject="Hesap dogrulama",
        body="Sifrenizi dogrulayin: http://paypa1-secure.tk/login",
        sender=("PayPal", "alerts@paypa1-secure.tk")))

    assert email.header_source == "rfc822"
    assert email.from_addr == "alerts@paypa1-secure.tk"
    assert email.reply_to == "destek@baska-domain.tk"
    assert "spf=fail" in email.auth_results[0]
    assert len(email.received) == 1
    ids = [i.id for i in analyzer.analyze(email).indicators]
    assert {"spf_fail", "dkim_fail", "dmarc_fail"} <= set(ids)
    assert "msg_no_transport_headers" not in ids


def test_body_content_type_is_ours_not_the_saved_one():
    """The saved headers describe a body we rebuilt, so Content-* must not leak."""
    email = parser.parse_bytes(B.message(
        transport=TRANSPORT + "Content-Type: text/plain; charset=iso-8859-9\r\n",
        body="merhaba", html="<p>merhaba</p>",
        sender=("PayPal", "alerts@paypa1-secure.tk")))
    assert email.html_body.strip() == "<p>merhaba</p>"
    assert len(email.headers.get("content-type", [])) == 1


# -- header fidelity: rebuilt from MAPI -----------------------------------


def test_headers_are_rebuilt_from_mapi_properties():
    email = parser.parse_bytes(phish_msg())

    assert email.header_source == "mapi"
    # From = the identity Outlook shows (sent-representing), not the account.
    assert email.from_display == "PayPal Guvenlik"
    assert email.from_addr == "alerts@paypa1-secure.tk"
    assert email.headers["sender"] == ["PayPal Guvenlik <noreply@contoso-mail.tk>"]
    assert email.to == "Ali <ali@example.com>"
    assert email.headers["cc"] == ["Veli <veli@example.com>"]
    assert "14 Aug 2026" in email.date
    assert [l.href for l in email.links] == ["http://guvenli-giris.tk/oturum",
                                             "http://paypa1-secure.tk/login"]


def test_missing_internet_headers_are_reported_not_scored():
    result = analyzer.analyze(parser.parse_bytes(phish_msg()))
    note = next(i for i in result.indicators if i.id == "msg_no_transport_headers")

    assert note.weight == 0                      # cannot move the score
    assert note.id in SOFT_IDS                   # cannot drive the verdict
    assert note.id in mitre.NO_TECHNIQUE         # not adversary tradecraft
    assert "dogrulanamiyor" in note.explanation


def test_absent_received_chain_is_not_called_injection():
    """Outlook dropping the headers must not read as a spoofing finding."""
    ids = [i.id for i in analyzer.analyze(parser.parse_bytes(phish_msg())).indicators]
    assert "no_received_headers" not in ids


def test_benign_msg_without_headers_stays_low():
    result = analyzer.analyze(parser.parse_bytes(B.message(
        subject="Toplanti notlari",
        body="Merhaba Ali, ekteki notlara bakabilir misin?",
        sender=("Ayse Yilmaz", "ayse@example.com"),
        recipients=[("Ali", "ali@example.com", 1)])))
    assert result.verdict == "low"
    assert result.breakdown.hard == 0


def test_identity_checks_still_fire_without_internet_headers():
    ids = [i.id for i in analyzer.analyze(parser.parse_bytes(phish_msg())).indicators]
    assert "brand_impersonation" in ids       # PayPal display name, other domain
    assert "anchor_href_mismatch" in ids      # link text says paypal.com


# -- folder scans ---------------------------------------------------------


def test_batch_scans_msg_next_to_eml(tmp_path, capsys):
    (tmp_path / "a.eml").write_bytes(
        b"From: a@example.com\r\nSubject: merhaba\r\n\r\nselam")
    (tmp_path / "b.msg").write_bytes(phish_msg())

    code = cli.main(["batch", str(tmp_path)])
    out = capsys.readouterr().out

    assert code == 0
    assert "a.eml" in out and "b.msg" in out


def test_batch_reports_a_corrupt_msg_instead_of_skipping_it(tmp_path, capsys):
    (tmp_path / "bad.msg").write_bytes(msg.SIGNATURE + b"\x00" * 600)

    code = cli.main(["batch", str(tmp_path)])
    captured = capsys.readouterr()

    assert code == 1
    assert "bad.msg" in captured.err
    assert "bad.msg" in captured.out
