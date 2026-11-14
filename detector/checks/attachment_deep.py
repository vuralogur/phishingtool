"""Tier 2 - deep static inspection of attachment *content* (not just names).

Three families, all static (files are never opened/executed):
  * HTML smuggling  - an .html/.htm attachment that reconstructs a payload in
    the browser via base64 + Blob/msSaveOrOpenBlob/data: download.
  * Office macros   - OLE (D0CF11E0) or a `vbaProject.bin` inside an OOXML zip;
    if oletools is installed we also flag auto-exec macro keywords.
  * PDF active bits  - /JS /JavaScript /OpenAction /AA /Launch /EmbeddedFile.

oletools is optional; everything else is stdlib byte scanning.
"""
from __future__ import annotations
import re

from ..indicators import Indicator

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

_HTML_EXT = {"html", "htm", "shtml"}
_OLE_EXT = {"doc", "xls", "ppt", "dot"}


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

        # --- HTML smuggling ---
        if ext in _HTML_EXT or att.content_type.lower() in ("text/html", "application/xhtml+xml"):
            if _SMUGGLE_SIG.search(data) and _BASE64_BLOB.search(data):
                out.append(Indicator("html_smuggling", "attachment", "high", 20,
                    "HTML ek tarayicida payload kuruyor (Blob/base64/otomatik indirme): " + att.filename,
                    "HTML smuggling - zararli dosya agdan degil, sayfanin icindeki base64'ten uretilir; ag filtrelerini atlatir."))

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
