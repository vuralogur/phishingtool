"""Legitimate mail that used to be flagged - and the phish that must still be.

Every fix here narrows an indicator, so each one is tested from both sides: the
ordinary mail no longer trips it, and the attack it was written for still does.
"""
import json
from email.message import EmailMessage

import pytest

from detector import analyzer, config, parser, report
from detector.checks import attachment_deep, attachments, content, headers, url_deep
from detector.indicators import Indicator
from detector.scoring import AUTH_FAIL_IDS, SOFT_IDS, THRESHOLDS, score

CTX = analyzer.build_context(config=config.DEFAULTS)

RECEIVED = ("from mail.sender.example (mail.sender.example [8.8.8.8]) by "
            "mx.victim.example with ESMTPS id x1; Tue, 05 Aug 2025 09:00:01 +0000")
DMARC_PASS = "mx.victim.example; spf=pass; dkim=pass; dmarc=pass"


def _mail(frm="Bilgi <info@firma-ornek.com>", body="Merhaba.", html=None,
          auth=None, received=True, reply_to=None, attach=None):
    m = EmailMessage()
    if received:
        m["Received"] = RECEIVED
    if auth:
        m["Authentication-Results"] = auth
    m["From"] = frm
    m["To"] = "user@victim.example"
    m["Subject"] = "Bilgilendirme"
    if reply_to:
        m["Reply-To"] = reply_to
    if html is not None:
        m.set_content(html, subtype="html")
    else:
        m.set_content(body)
    for data, maintype, subtype, name in attach or ():
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return parser.parse_bytes(m.as_bytes())


def _by_id(result):
    return {i.id: i for i in result.indicators}


def _link_ids(host, ctx=CTX):
    email = _mail(html="<a href='https://" + host + "/x'>link</a>")
    return {i.id for i in url_deep.run(email, ctx=ctx)}


# ---------------------------------------------------------------------------
# combosquat_domain: brand + a lure word, not brand + anything
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "storage.googleapis.com", "s3.amazonaws.com", "m.media-amazon.com",
    "www.paypalobjects.com", "raw.githubusercontent.com",
    "lh3.googleusercontent.com", "www.dropboxusercontent.com",
    "www.microsoft365.com", "googlemail.com",
    "www.ziraatkatilim.com.tr", "www.garantiemeklilik.com.tr",
    "www.akbanksanat.com", "www.turkcellsuperonline.com",
    "www.pineapple.com", "www.applebees.com", "www.zoominfo.com",
    "www.bookingholdings.com",
])
def test_brand_infrastructure_and_ordinary_words_are_not_combosquats(host):
    assert "combosquat_domain" not in _link_ids(host)


@pytest.mark.parametrize("host, words", [
    ("paypal-secure.com", "secure"),
    ("secure-login-paypal.net", "secure, login"),
    ("paypalsecurelogin24.com", "securelogin"),          # glued, digits ignored
    ("apple-id-support.com", "id, support"),
    ("microsoft-account-verify.com", "account, verify"),
    ("netflix-billing-update.com", "billing, update"),
    ("garantibbva-destek.com", "destek"),
    ("akbankgiris.com", "giris"),
    ("akbank-internet-subesi.com", "internet, subesi"),
    ("hepsiburada-kampanya.com", "kampanya"),
    ("trendyol-iade-destek.com", "iade, destek"),
])
def test_brand_plus_lure_word_is_a_combosquat(host, words):
    email = _mail(html="<a href='https://" + host + "/x'>link</a>")
    found = [i for i in url_deep.run(email, ctx=CTX) if i.id == "combosquat_domain"]
    assert found, host
    assert "tuzak kelime (" + words + ")" in found[0].evidence


def test_the_real_brand_domain_is_never_a_combosquat():
    assert "combosquat_domain" not in _link_ids("www.paypal.com")
    assert "combosquat_domain" not in _link_ids("login.microsoftonline.com")


def test_lure_words_come_from_the_context_dictionary():
    custom = {**CTX, "lure_words": {"objects"}}
    assert "combosquat_domain" in _link_ids("www.paypalobjects.com", custom)
    assert "combosquat_domain" not in _link_ids("paypal-secure.com", custom)
    # No dictionary at all (a direct call without a context): nothing to match.
    assert "combosquat_domain" not in _link_ids("paypal-secure.com", {**CTX, "lure_words": set()})


def test_lure_words_written_with_turkish_letters_still_match():
    custom = {**CTX, "lure_words": {"şifre"}}
    assert "combosquat_domain" in _link_ids("akbank-sifre.com", custom)


def test_data_dir_without_lure_words_falls_back_to_the_bundled_list(tmp_path):
    """A --data-dir made before the file existed must not disable the check."""
    (tmp_path / "brands.txt").write_text("paypal,paypal.com\n", encoding="utf-8")
    ctx = analyzer.build_context(data_dir=tmp_path, config=config.DEFAULTS)
    assert "secure" in ctx["lure_words"]
    assert "combosquat_domain" in _link_ids("paypal-secure.com", ctx)

    (tmp_path / "lure_words.txt").write_text("ozelkelime\n", encoding="utf-8")
    ctx = analyzer.build_context(data_dir=tmp_path, config=config.DEFAULTS)
    assert ctx["lure_words"] == {"ozelkelime"}


# ---------------------------------------------------------------------------
# credential_request: giving a number is not asking for one
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    "Ekim faturaniz ektedir. Odeme icin IBAN: TR00 0000 0000 0000 0000 0000 00",
    "Havale icin IBAN numaramiz asagidadir.",
    "Musteri numaraniz: 1234567. Faturaniz ektedir.",
    "Müşteri numarası 1234567 olan aboneliğiniz yenilendi.",
])
def test_bill_details_are_not_a_credential_request(body):
    email = _mail(body=body)
    assert "credential_request" not in {i.id for i in content.run(email, ctx=CTX)}


@pytest.mark.parametrize("body", [
    "Iade icin IBAN bilgilerinizi bu maile yanitlayarak gonderin.",
    "Lütfen IBAN numaranızı ve TC kimlik numaranızı iletin.",
    "Odeme icin IBAN'ınızı yazın.",
    "Devam etmek icin musteri numaranizi ve sifrenizi girin.",
    "Please confirm your password to keep your account.",
    "Kart numaranız ve CVV kodunuz gerekli.",
])
def test_asking_for_secrets_is_still_a_credential_request(body):
    email = _mail(body=body)
    assert "credential_request" in {i.id for i in content.run(email, ctx=CTX)}


def test_password_reset_from_an_authenticated_sender_stays_low():
    email = _mail(frm="GitHub <noreply@github.com>", auth=DMARC_PASS,
                  html="<p>Click to reset your password.</p>"
                       "<a href='https://github.com/password_reset/abc'>Reset</a>")
    r = analyzer.analyze(email, ctx=CTX)
    ind = _by_id(r)["credential_request"]
    assert (ind.weight, ind.severity) == (6, "medium")
    assert "DMARC pass" in ind.evidence
    assert r.verdict == "low" and r.breakdown.reason == "weak_hard_evidence"


def test_password_talk_from_an_unauthenticated_sender_keeps_full_weight():
    email = _mail(html="<p>Click to reset your password.</p>")
    r = analyzer.analyze(email, ctx=CTX)
    assert _by_id(r)["credential_request"].weight == 12
    assert r.verdict == "medium"


def test_a_self_written_pass_does_not_buy_the_credential_discount():
    """dmarc=pass with no Received line is the sender's own claim (see headers)."""
    email = _mail(auth=DMARC_PASS, received=False,
                  html="<p>Click to reset your password.</p>")
    assert _by_id(analyzer.analyze(email, ctx=CTX))["credential_request"].weight == 12


def test_reduced_credential_weight_still_corroborates_other_evidence():
    email = _mail(frm="Destek <destek@firma-ornek.com>", auth=DMARC_PASS,
                  html="<p>Sifrenizi girin.</p><form action='https://collect.evil-site.com/p'>"
                       "<input type='password'></form>")
    r = analyzer.analyze(email, ctx=CTX)
    assert _by_id(r)["credential_request"].weight == 6
    assert r.verdict in ("high", "critical")      # 6 + 18 + 16


# ---------------------------------------------------------------------------
# PDF: exact names, and a trigger is not a payload
# ---------------------------------------------------------------------------

def _pdf_ids(data):
    email = _mail(attach=[(data, "application", "pdf", "fatura.pdf")])
    return {i.id: i for i in attachment_deep.run(email)}


@pytest.mark.parametrize("data", [
    b"%PDF-1.7\n5 0 obj<</Type/Font/BaseFont/AAAAAA+Roboto-Regular>>endobj\n%%EOF",
    b"%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction[3 0 R/Fit]>>endobj\n%%EOF",
    b"%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction[3 0 R/Fit]>>endobj\n"
    b"5 0 obj<</BaseFont/AAAAAA+Roboto/FontFile2 6 0 R>>endobj\n%%EOF",
    b"%PDF-1.7\n1 0 obj<</Type/Page/AA<</O 7 0 R>>>>endobj\n%%EOF",   # trigger, no script
    b"%PDF-1.7\n1 0 obj<</Filter/JSONDecode /JSX 1 /LaunchPad 2 /AAC 3>>endobj\n%%EOF",
])
def test_ordinary_pdfs_are_not_active_content(data):
    assert not _pdf_ids(data)


def test_pdf_script_is_reported_with_the_trigger_that_runs_it():
    ids = _pdf_ids(b"%PDF-1.7\n1 0 obj<</OpenAction<</S/JavaScript/JS(app.alert(1))>>>>endobj")
    ind = ids["pdf_active_content"]
    assert "/JavaScript" in ind.evidence and "/OpenAction" in ind.evidence
    assert "pdf_embedded_file" not in ids

    for data in (b"%PDF-1.7 /AA<</O<</JS 9 0 R>>>>", b"%PDF-1.7 /JS\n(x)", b"%PDF-1.7 /JS<414243>"):
        assert "pdf_active_content" in _pdf_ids(data), data


def test_pdf_launch_needs_the_exact_name():
    assert "pdf_launch_action" in _pdf_ids(b"%PDF-1.7 /Launch<</F(cmd.exe)>>")
    assert "pdf_launch_action" not in _pdf_ids(b"%PDF-1.7 /LaunchPad 1")


def test_embedded_file_without_a_script_is_soft_context():
    ids = _pdf_ids(b"%PDF-1.7\n1 0 obj<</Type/EmbeddedFile/Subtype/text#2Fxml>>endobj")
    assert set(ids) == {"pdf_embedded_file"}
    assert "pdf_embedded_file" in SOFT_IDS
    assert ids["pdf_embedded_file"].technique == "T1027.009"
    # e-invoice shape (PDF/A-3 with an XML inside) from a proven sender: low.
    email = _mail(auth=DMARC_PASS, attach=[(
        b"%PDF-1.7\n1 0 obj<</OpenAction[3 0 R/Fit]/Type/EmbeddedFile>>endobj",
        "application", "pdf", "e-fatura.pdf")])
    assert analyzer.analyze(email, ctx=CTX).verdict == "low"


# ---------------------------------------------------------------------------
# Macros: an OLE container is not a macro
# ---------------------------------------------------------------------------

OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512
VBA_ENTRY = "_VBA_PROJECT".encode("utf-16-le")


def _doc_ids(data, name="sozlesme.doc", subtype="msword"):
    email = _mail(attach=[(data, "application", subtype, name)])
    return {i.id for i in attachment_deep.run(email)}


def test_legacy_office_file_without_vba_is_not_a_macro(monkeypatch):
    monkeypatch.setattr(attachment_deep, "_macro_scan", lambda data: (None, []))
    assert "macro_detected" not in _doc_ids(OLE)
    assert "macro_detected" not in _doc_ids(OLE, "eski.xls", "vnd.ms-excel")
    # Saved Outlook messages are OLE containers too.
    assert "macro_detected" not in _doc_ids(OLE, "ileti.msg", "vnd.ms-outlook")


def test_ole_file_with_a_vba_project_is_a_macro_without_oletools(monkeypatch):
    monkeypatch.setattr(attachment_deep, "_macro_scan", lambda data: (None, []))
    assert "macro_detected" in _doc_ids(OLE + VBA_ENTRY + b"\x00" * 64)
    assert "macro_detected" in _doc_ids(b"PK\x03\x04 word/vbaProject.bin", "b.docm",
                                        "vnd.ms-word.document.macroEnabled.12")


def test_oletools_verdict_wins_when_it_could_read_the_file(monkeypatch):
    with_marker = OLE + VBA_ENTRY
    monkeypatch.setattr(attachment_deep, "_macro_scan", lambda data: (False, []))
    assert "macro_detected" not in _doc_ids(with_marker)   # it looked: no macro
    monkeypatch.setattr(attachment_deep, "_macro_scan", lambda data: (True, []))
    assert "macro_detected" in _doc_ids(OLE)
    monkeypatch.setattr(attachment_deep, "_macro_scan", lambda data: (True, ["AutoOpen"]))
    assert "macro_autoexec" in _doc_ids(OLE)


def test_plain_legacy_doc_from_a_proven_sender_is_low():
    email = _mail(auth=DMARC_PASS,
                  attach=[(OLE, "application", "msword", "sozlesme.doc")])
    assert analyzer.analyze(email, ctx=CTX).verdict == "low"


# ---------------------------------------------------------------------------
# Auth failures: one root cause, counted once
# ---------------------------------------------------------------------------

AUTH_FAIL = {"spf": "fail", "dkim": "fail", "dmarc": "fail"}


def _auth_trio():
    return [Indicator("spf_fail", "auth", "high", 15, "e", "x"),
            Indicator("dkim_fail", "auth", "high", 12, "e", "x"),
            Indicator("dmarc_fail", "auth", "high", 15, "e", "x")]


def test_failing_all_three_mechanisms_is_medium_not_high():
    r = score(_auth_trio(), AUTH_FAIL)
    b = r.breakdown
    assert (b.hard, b.hard_count) == (20, 3)
    assert (b.auth_raw, b.auth_trimmed) == (42, 22)
    assert r.score == 20 and r.verdict == "medium" and b.reason == "hard_medium"


def test_forwarded_list_mail_with_clean_content_is_medium():
    email = _mail(frm="Proje Listesi <dev@lists.ornek-proje.org>",
                  auth="mx.victim.example; spf=fail; dkim=fail; dmarc=fail",
                  html="<p>Yeni surum yayinlandi.</p>")
    r = analyzer.analyze(email, ctx=CTX)
    assert {"spf_fail", "dkim_fail", "dmarc_fail"} <= set(_by_id(r))
    assert r.verdict == "medium"


def test_auth_failure_plus_independent_evidence_still_escalates():
    r = score(_auth_trio() + [Indicator("brand_impersonation", "content", "high", 16, "e", "x")],
              AUTH_FAIL)
    assert r.breakdown.hard == 36 and r.verdict == "high"
    r = score(_auth_trio() + [Indicator("brand_impersonation", "content", "high", 16, "e", "x"),
                              Indicator("anchor_href_mismatch", "url", "high", 20, "e", "x")],
              AUTH_FAIL)
    assert r.verdict == "critical"


def test_live_rechecks_share_the_same_cap():
    live = [Indicator("spf_live_fail", "auth", "high", 15, "e", "x"),
            Indicator("dkim_verify_fail", "auth", "high", 15, "e", "x"),
            Indicator("dmarc_policy_violation", "auth", "high", 15, "e", "x")]
    r = score(_auth_trio() + live, AUTH_FAIL)
    assert r.breakdown.hard == THRESHOLDS["auth_cap"] and r.verdict == "medium"
    assert {i.id for i in _auth_trio() + live} <= AUTH_FAIL_IDS


def test_a_single_auth_failure_is_untouched():
    r = score([Indicator("dmarc_fail", "auth", "high", 15, "e", "x")], AUTH_FAIL)
    assert (r.breakdown.hard, r.breakdown.auth_raw, r.breakdown.auth_trimmed) == (15, 0, 0)
    assert "auth ailesi" not in "\n".join(report.breakdown_lines(r))


def test_the_cap_is_shown_in_the_breakdown_and_json():
    r = score(_auth_trio(), AUTH_FAIL)
    first = report.breakdown_lines(r)[0]
    assert "sert 20 (3 gösterge; auth ailesi 42→20)" in first
    d = json.loads(report.to_json(r))["breakdown"]
    assert (d["auth_raw"], d["auth_trimmed"]) == (42, 22)


def test_auth_cap_is_configurable(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("[thresholds]\nauth_cap = 100\n", encoding="utf-8")
    cfg = config.load(p)
    assert cfg.changed == ("thresholds",)
    r = score(_auth_trio(), AUTH_FAIL, config=cfg)
    assert r.breakdown.hard == 42 and r.verdict == "high"      # the old behaviour
    assert config.DEFAULTS.thresholds["auth_cap"] == 20


def test_auth_indicators_moved_to_soft_are_outside_the_cap(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('[soft_ids]\nadd = ["spf_fail", "dkim_fail"]\n', encoding="utf-8")
    r = score(_auth_trio(), AUTH_FAIL, config=config.load(p))
    assert (r.breakdown.hard, r.breakdown.soft_raw) == (15, 27)
    assert r.breakdown.auth_trimmed == 0


# ---------------------------------------------------------------------------
# Reply-To: a help desk is not a BEC
# ---------------------------------------------------------------------------

def test_reply_to_a_helpdesk_from_an_authenticated_sender_stays_low():
    email = _mail(frm="Magaza <bulten@magaza-ornek.com.tr>", auth=DMARC_PASS,
                  reply_to="destek@magaza-ornek.zendesk.com",
                  html="<p>Merhaba Ahmet, siparisiniz yola cikti.</p>")
    r = analyzer.analyze(email, ctx=CTX)
    ind = _by_id(r)["from_replyto_mismatch"]
    assert (ind.weight, ind.severity) == (5, "low")
    assert "dusuk agirlik" in ind.explanation
    assert r.verdict == "low"


@pytest.mark.parametrize("auth, reply_to", [
    (DMARC_PASS, "ahmet.yilmaz.mudur@gmail.com"),      # free mailbox: the BEC shape
    (None, "destek@magaza-ornek.zendesk.com"),         # sender not proven
    ("mx.victim.example; spf=pass", "destek@baska-firma.com"),   # partial is not proof
])
def test_reply_to_mismatch_keeps_full_weight_otherwise(auth, reply_to):
    email = _mail(frm="Magaza <bulten@magaza-ornek.com.tr>", auth=auth, reply_to=reply_to)
    r = analyzer.analyze(email, ctx=CTX)
    assert _by_id(r)["from_replyto_mismatch"].weight == 10
    assert r.verdict == "medium"


def test_reply_to_check_works_without_a_context():
    email = _mail(reply_to="x@baska-firma.com")
    found = [i for i in headers.run(email) if i.id == "from_replyto_mismatch"]
    assert found and found[0].weight == 10


# ---------------------------------------------------------------------------
# MIME / extension: aliases are not mismatches
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("maintype, subtype, name", [
    ("application", "x-zip-compressed", "belgeler.zip"),   # what Windows sends
    ("application", "x-zip", "belgeler.zip"),
    ("application", "octet-stream", "fatura.pdf"),         # "some bytes"
    ("application", "x-pdf", "fatura.pdf"),
    ("image", "jpg", "foto.jpg"),
    ("image", "pjpeg", "foto.jpeg"),
    ("application", "octet-stream", "sozlesme.docx"),
])
def test_common_mime_spellings_are_not_a_mismatch(maintype, subtype, name):
    email = _mail(attach=[(b"data", maintype, subtype, name)])
    assert "mime_extension_mismatch" not in {i.id for i in attachments.run(email)}


@pytest.mark.parametrize("maintype, subtype, name", [
    ("text", "html", "fatura.pdf"),
    ("application", "x-msdownload", "fatura.pdf"),
    ("application", "pdf", "foto.jpg"),
    ("application", "javascript", "belgeler.zip"),
])
def test_a_real_mime_contradiction_is_still_reported(maintype, subtype, name):
    email = _mail(attach=[(b"data", maintype, subtype, name)])
    assert "mime_extension_mismatch" in {i.id for i in attachments.run(email)}
