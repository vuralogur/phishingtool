"""Tier 2 - deep static inspection of attachment *content* (not just names).

Four families, all static (files are never opened/executed):
  * HTML smuggling  - an .html/.htm attachment that reconstructs a payload in
    the browser via base64 + Blob/msSaveOrOpenBlob/data: download.
  * Attached pages  - an HTML/SVG attachment read like the body is: a login
    form, or script that redirects / hides itself (one finding per file).
  * Office macros   - OLE (D0CF11E0) or a `vbaProject.bin` inside an OOXML zip;
    if oletools is installed we also flag auto-exec macro keywords.
  * PDF active bits  - /JS /JavaScript /OpenAction /AA /Launch /EmbeddedFile.

oletools is optional; everything else is stdlib byte scanning.
"""
from __future__ import annotations
import re

from ..indicators import Indicator
from . import html_forensics

_SMUGGLE_SIG = re.compile(
    rb"(msSaveOrOpenBlob|new\s+Blob\s*\(|createObjectURL|"
    rb"application/octet-stream|download\s*=|atob\s*\()",
    re.IGNORECASE,
)
_BASE64_BLOB = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")

def _pdf_name(name: bytes):
    """Match a PDF name object exactly.

    A name runs until whitespace or a delimiter, so a plain substring test for
    "/AA" also hit every subset-font tag ("/AAAAAA+Roboto") - which is to say
    almost every PDF a browser or an office suite has ever exported.
    """
    return re.compile(re.escape(name) + rb"(?![^\s\x00()<>\[\]{}/%])")


# Code inside the document. This is the finding.
_PDF_SCRIPT = [
    (_pdf_name(b"/JavaScript"), "gomulu JavaScript (/JavaScript)"),
    (_pdf_name(b"/JS"), "gomulu JavaScript (/JS)"),
]
# "Do something when the file opens." On its own this is how a PDF sets its
# starting page and zoom, so it is only reported next to something worth
# triggering - it explains the script, it is not evidence by itself.
_PDF_TRIGGER = [
    (_pdf_name(b"/OpenAction"), "acilista otomatik calisir (/OpenAction)"),
    (_pdf_name(b"/AA"), "otomatik aksiyon (/AA)"),
]
_PDF_LAUNCH = _pdf_name(b"/Launch")
_PDF_EMBEDDED = _pdf_name(b"/EmbeddedFile")

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# Directory entries of an OLE container are stored uncompressed as UTF-16, so a
# VBA project announces itself by name even without parsing the container.
_VBA_STORAGE = "_VBA_PROJECT".encode("utf-16-le")

_HTML_EXT = {"html", "htm", "shtml", "xhtml", "xht"}
_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_OLE_EXT = {"doc", "xls", "ppt", "dot"}

# Script that sends the reader somewhere else. Case-sensitive on purpose: this
# is JavaScript's own spelling, not the word "Location" in a sentence.
_NAVIGATE = re.compile(
    r"\blocation(?:\.href)?\s*=(?!=)|\blocation\.(?:replace|assign)\s*\("
    r"|\bwindow\.open\s*\(")
# The same thing written into an event handler: <body onload="location=...">.
_HANDLER_NAVIGATE = re.compile(
    r"""\bon[a-z]+\s*=\s*(["'])[^"']*?(?:location|window\.open)""", re.IGNORECASE)
# An image format has no business carrying any of these.
_SVG_ACTIVE = re.compile(
    r"<script\b|\son[a-z]+\s*=|javascript:|<iframe\b|<embed\b", re.IGNORECASE)


def _text(data: bytes) -> str:
    """Attachment bytes as markup text; a wrong guess only costs some accents."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _page(att, data: bytes, is_svg: bool):
    """Read an HTML/SVG attachment the way the body is read (html_forensics).

    A page that arrives as a file opens from the local disk: there is no "own
    domain" for a form to post back to, and no URL filter between the reader
    and wherever a script sends them. At most ONE finding per file - a login
    page that also redirects is one phishing page, not two pieces of evidence -
    and the form, being the more specific statement, wins.
    """
    text = _text(data)
    s = html_forensics.scan(text)
    posts = sorted({h for h in (html_forensics.host_of(a) for a in s.form_actions) if h})
    if s.has_password or posts:
        what = (["parola alani"] if s.has_password else []) + \
               (["form verisi gidiyor: " + ", ".join(posts[:3])] if posts else [])
        return Indicator("html_attachment_form", "attachment", "high", 16,
            att.filename + ": ekteki sayfada giris formu (" + "; ".join(what) + ")",
            "Ek olarak gelen sayfa tarayicida yerel dosya olarak acilir ve "
            "girilen bilgiyi disari yollar - kimlik avi sayfasinin kendisi.")

    why = []
    if s.meta_refresh and html_forensics.host_of(s.meta_refresh):
        why.append("meta-refresh: " + html_forensics.host_of(s.meta_refresh))
    if any(_NAVIGATE.search(b) for b in s.scripts) or _HANDLER_NAVIGATE.search(text):
        why.append("betik baska adrese yonlendiriyor")
    if html_forensics.has_obfuscated_script(s):
        why.append("gizlenmis betik (eval/atob/fromCharCode)")
    if is_svg and _SVG_ACTIVE.search(text):
        why.append("SVG icinde betik/olay isleyici")
    if why:
        return Indicator("html_attachment_script", "attachment", "high", 14,
            att.filename + ": " + "; ".join(why),
            "Ekteki sayfa acildigi an kod calistiriyor ya da okuyucuyu baska "
            "adrese goturuyor; hedef mailin icinde link olarak hic gorunmez.")
    return None


def _macro_scan(data: bytes):
    """Return (found, autoexec_keywords) using oletools if installed.

    found is True/False when oletools ran, None when it is unavailable.
    """
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
    except Exception:
        return None, []
    vp = None
    try:
        vp = VBA_Parser("att", data=data)
        if not vp.detect_vba_macros():
            return False, []
        try:
            results = vp.analyze_macros()
            autos = [kw for typ, kw, _ in results if typ in ("AutoExec", "Suspicious")]
        except Exception:
            autos = []
        return True, autos
    except Exception:
        return None, []
    finally:
        if vp is not None:
            try:
                vp.close()
            except Exception:
                pass


def run(email, online=False, ctx=None):
    out = []
    for att in email.attachments:
        data = att.payload or b""
        ext = att.ext
        if not data:
            continue

        # --- HTML / SVG pages delivered as files ---
        ctype = att.content_type.lower()
        is_svg = ext == "svg" or ctype == "image/svg+xml"
        if ext in _HTML_EXT or ctype in _HTML_TYPES or is_svg:
            if _SMUGGLE_SIG.search(data) and _BASE64_BLOB.search(data):
                out.append(Indicator("html_smuggling", "attachment", "high", 20,
                    "HTML ek tarayicida payload kuruyor (Blob/base64/otomatik indirme): " + att.filename,
                    "HTML smuggling - zararli dosya agdan degil, sayfanin icindeki base64'ten uretilir; ag filtrelerini atlatir."))
            page = _page(att, data, is_svg)
            if page:
                out.append(page)

        # --- Office macros ---
        # Being an OLE file is not having a macro: every .doc/.xls/.ppt saved
        # before 2007 - and every .msg - is one. The container has to actually
        # hold a VBA project.
        is_ole = data[:8] == _OLE_MAGIC
        has_vba = ((is_ole and _VBA_STORAGE in data)
                   or (data[:2] == b"PK" and b"vbaProject.bin" in data))
        if is_ole or has_vba or ext in _OLE_EXT:
            # oletools, when installed, is the authority (found is True/False).
            # Without it - or when it could not read the file - fall back to
            # what the container itself announces.
            found, autos = _macro_scan(data)
            if autos:
                out.append(Indicator("macro_autoexec", "attachment", "critical", 22,
                    att.filename + ": otomatik calisan/supheli makro - " + ", ".join(sorted(set(autos))[:5]),
                    "Belge acildiginda makro kendiliginden calisir (AutoOpen/Shell vb.)."))
            elif found or (found is None and has_vba):
                out.append(Indicator("macro_detected", "attachment", "high", 18,
                    "Belgede VBA makro var: " + att.filename,
                    "Makrolu belge acildiginda etkinlestirilirse kod calisir."))

        # --- PDF active content ---
        if ext == "pdf" or data[:5] == b"%PDF-":
            scripts = [desc for rx, desc in _PDF_SCRIPT if rx.search(data)]
            triggers = [desc for rx, desc in _PDF_TRIGGER if rx.search(data)]
            embedded = bool(_PDF_EMBEDDED.search(data))
            if _PDF_LAUNCH.search(data):
                out.append(Indicator("pdf_launch_action", "attachment", "high", 20,
                    att.filename + ": PDF /Launch ile harici program calistirmaya calisiyor",
                    "/Launch acilista disaridan komut/dosya calistirabilir."))
            if scripts:
                hits = scripts + triggers + (["gomulu dosya (/EmbeddedFile)"] if embedded else [])
                out.append(Indicator("pdf_active_content", "attachment", "high", 16,
                    att.filename + ": " + ", ".join(hits[:4]),
                    "PDF icinde calisan kod var - zararsiz faturada bulunmaz."))
            elif embedded:
                # No script to drop or open it: an attachment inside the PDF,
                # which e-invoices (PDF/A-3, ZUGFeRD) and portfolios also carry.
                out.append(Indicator("pdf_embedded_file", "attachment", "low", 6,
                    att.filename + ": PDF icinde gomulu dosya (/EmbeddedFile), betik yok",
                    "PDF baska bir dosya tasiyor. E-fatura (PDF/A-3) ve portfoylerde "
                    "olagandir; ayni yol zararli belge tasimak icin de kullanilir."))
    return out
