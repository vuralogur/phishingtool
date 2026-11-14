"""Attachment checks: dangerous extensions, double extensions, MIME mismatch."""
from __future__ import annotations

from ..indicators import Indicator

DANGEROUS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "jar", "ps1", "msi", "lnk", "reg", "html", "htm", "svg",
}
MACRO = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE = {"zip", "rar", "7z", "iso", "img"}

# Extensions that are commonly used as the harmless-looking first half of a
# double extension (e.g. invoice.pdf.exe).
BENIGN_LOOKING = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}

# Every MIME type real mail clients use for the extension - not just the
# registered one. Windows labels a zip "application/x-zip-compressed", and plenty
# of senders say "image/jpg"; reporting those buried the real mismatches.
_JPEG = {"image/jpeg", "image/jpg", "image/pjpeg"}
MIME_EXPECT = {
    "pdf": {"application/pdf", "application/x-pdf"},
    "png": {"image/png", "image/x-png"},
    "jpg": _JPEG,
    "jpeg": _JPEG,
    "zip": {"application/zip", "application/x-zip-compressed", "application/x-zip"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
             "application/msword"},
}
# "Some bytes" - the type a client falls back to when it does not know better.
# It claims nothing about the file, so it cannot contradict the extension.
MIME_GENERIC = {"application/octet-stream", "binary/octet-stream"}


def run(email, online=False, ctx=None):
    out = []
    for att in email.attachments:
        name = (att.filename or "").lower()
        ext = att.ext

        parts = name.rsplit(".", 2)
        if len(parts) == 3 and parts[1] in BENIGN_LOOKING and parts[2] in DANGEROUS:
            out.append(Indicator("double_extension", "attachment", "high", 18,
                "Çift uzantılı ek: " + att.filename,
                "Zararsız görünen ilk uzantının ardında çalıştırılabilir dosya gizli."))

        if ext in DANGEROUS:
            out.append(Indicator("dangerous_attachment", "attachment", "high", 20,
                "Tehlikeli uzantı: " + att.filename + " (" + att.content_type + ")",
                "Çalıştırılabilir/script eki — açılırsa kod çalışır."))
        elif ext in MACRO:
            out.append(Indicator("macro_document", "attachment", "medium", 12,
                "Makro içerebilen belge: " + att.filename,
                "Makrolu Office belgeleri zararlı kod taşıyabilir."))
        elif ext in ARCHIVE:
            out.append(Indicator("archive_attachment", "attachment", "low", 5,
                "Arşiv eki: " + att.filename,
                "Arşivler tarayıcılardan zararlı içerik gizlemekte kullanılır."))

        exp = MIME_EXPECT.get(ext)
        declared = (att.content_type or "").lower()
        if exp and declared and declared not in exp and declared not in MIME_GENERIC:
            out.append(Indicator("mime_extension_mismatch", "attachment", "medium", 10,
                att.filename + ": uzantı ." + ext + " ama MIME " + att.content_type,
                "Uzantı ile gerçek dosya türü uyuşmuyor — gizleme taktiği."))
    return out
