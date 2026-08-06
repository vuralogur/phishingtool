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

MIME_EXPECT = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "zip": "application/zip",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


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
        if exp and att.content_type and att.content_type.lower() != exp:
            out.append(Indicator("mime_extension_mismatch", "attachment", "medium", 10,
                att.filename + ": uzantı ." + ext + " ama MIME " + att.content_type,
                "Uzantı ile gerçek dosya türü uyuşmuyor — gizleme taktiği."))
    return out
