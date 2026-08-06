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

_PDF_ACTIVE = [
    (b"/OpenAction", "otomatik calisan aksiyon (/OpenAction)"),
    (b"/AA", "otomatik aksiyon (/AA)"),
    (b"/JavaScript", "gomulu JavaScript (/JavaScript)"),
    (b"/JS", "gomulu JavaScript (/JS)"),
    (b"/EmbeddedFile", "gomulu dosya (/EmbeddedFile)"),
]

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
        is_ole = data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        has_vba = is_ole or (data[:2] == b"PK" and b"vbaProject.bin" in data)
        if has_vba or ext in _OLE_EXT:
            found, autos = _macro_scan(data)
            if autos:
                out.append(Indicator("macro_autoexec", "attachment", "critical", 22,
                    att.filename + ": otomatik calisan/supheli makro - " + ", ".join(sorted(set(autos))[:5]),
                    "Belge acildiginda makro kendiliginden calisir (AutoOpen/Shell vb.)."))
            elif found or has_vba:
                out.append(Indicator("macro_detected", "attachment", "high", 18,
                    "Belgede VBA makro var: " + att.filename,
                    "Makrolu belge acildiginda etkinlestirilirse kod calisir."))

        # --- PDF active content ---
        if ext == "pdf" or data[:5] == b"%PDF-":
            hits = [desc for sig, desc in _PDF_ACTIVE if sig in data]
            if b"/Launch" in data:
                out.append(Indicator("pdf_launch_action", "attachment", "high", 20,
                    att.filename + ": PDF /Launch ile harici program calistirmaya calisiyor",
                    "/Launch acilista disaridan komut/dosya calistirabilir."))
            if hits:
                out.append(Indicator("pdf_active_content", "attachment", "high", 16,
                    att.filename + ": " + ", ".join(hits[:4]),
                    "PDF icinde otomatik calisan kod/gomulu dosya var - zararsiz faturada bulunmaz."))
    return out
