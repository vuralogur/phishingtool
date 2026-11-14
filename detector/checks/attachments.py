"""Attachment checks: what the file claims to be - name, MIME type, leading bytes.

Dangerous and double extensions, and the two ways an attachment can contradict
its own extension: the declared Content-Type, and the signature of the content
itself (``detector.filetype`` - byte comparison only, nothing is opened).
"""
from __future__ import annotations

from ..filetype import LABELS, sniff
from ..indicators import Indicator

# Opening one of these runs code, or hands the reader's machine to whatever the
# file points at. Modelled on what mail providers refuse to deliver at all.
DANGEROUS = {
    # programs and installers
    "exe", "scr", "com", "pif", "dll", "cpl", "sys", "msi", "msp", "mst",
    "msix", "msixbundle", "appx", "appxbundle", "appinstaller", "application",
    "jar", "jnlp", "apk",
    # scripts
    "bat", "cmd", "js", "jse", "mjs", "vbs", "vbe", "vb", "wsf", "wsh", "wsc",
    "sct", "hta", "ps1", "psm1", "shb",
    # shortcuts and system files that launch or fetch something when opened
    "lnk", "url", "scf", "reg", "msc", "ins", "isp", "diagcab",
    "library-ms", "search-ms", "settingcontent-ms",
    # documents whose format exists to run or pull in code
    "chm", "xll", "iqy", "one", "onepkg", "ade", "adp", "mde",
    # pages: opened from disk, in the browser, outside every URL filter
    "html", "htm", "shtml", "xhtml", "xht", "mht", "mhtml", "svg",
}
MACRO = {"docm", "xlsm", "xlsb", "xltm", "pptm", "potm", "ppsm", "ppam", "sldm",
         "dotm", "xlam", "xla"}
ARCHIVE = {"zip", "rar", "7z", "iso", "img", "vhd", "vhdx", "cab", "gz", "tgz",
           "tar", "bz2", "xz", "arj", "ace", "lzh", "dmg", "wim"}

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

# What the leading bytes of a file with this extension may be (filetype kinds).
# Deliberately short and loose: only extensions whose format has a signature,
# and every kind that honestly turns up under them. Any image under any image
# extension (phones label PNG as .jpg all day); an OLE container under .docx
# (that is what a password-protected OOXML file is). Legacy .doc/.xls are left
# out - web exports saved as .xls are HTML or RTF and nobody means harm by it.
_IMAGE = {"image"}
_OOXML = {"zip", "ole"}
CONTENT_EXPECT = {
    "pdf": {"pdf"},
    "png": _IMAGE, "jpg": _IMAGE, "jpeg": _IMAGE, "gif": _IMAGE, "webp": _IMAGE,
    "bmp": _IMAGE, "tif": _IMAGE, "tiff": _IMAGE,
    "docx": _OOXML, "xlsx": _OOXML, "pptx": _OOXML,
    "docm": _OOXML, "xlsm": _OOXML, "pptm": _OOXML,
    "zip": {"zip", "archive"}, "rar": {"archive", "zip"}, "7z": {"archive", "zip"},
}


def run(email, online=False, ctx=None):
    out = []
    for att in email.attachments:
        # clean_name / ext: as the OS will see it ("fatura.exe." is fatura.exe).
        name = att.clean_name.lower()
        ext = att.ext

        parts = [p.strip() for p in name.rsplit(".", 2)]
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

        # The content itself. "" = unrecognised bytes, which proves nothing.
        kind = sniff(att.payload or b"")
        shown = att.filename + ": " + ("uzantı ." + ext if ext else "uzantı yok")
        contradicted = False
        if kind == "exe" and ext not in DANGEROUS:
            # Under an executable extension the name already says it
            # (dangerous_attachment); here the name says something else.
            contradicted = True
            out.append(Indicator("disguised_executable", "attachment", "high", 18,
                shown + " ama içerik " + LABELS[kind],
                "Dosya adı zararsız görünüyor, içerik ise program. Uzantıya bakan "
                "filtreleri atlatmak için kullanılır; meşru ekte görülmez."))
        elif kind and ext in CONTENT_EXPECT and kind not in CONTENT_EXPECT[ext]:
            contradicted = True
            out.append(Indicator("content_extension_mismatch", "attachment", "medium", 10,
                shown + " ama içerik " + LABELS[kind],
                "Dosyanın ilk baytları uzantının söylediği türe ait değil."))

        exp = MIME_EXPECT.get(ext)
        declared = (att.content_type or "").lower()
        # One lie, one finding: when the bytes already contradict the extension,
        # a MIME type that also disagrees is the same observation again.
        if (not contradicted and exp and declared and declared not in exp
                and declared not in MIME_GENERIC):
            out.append(Indicator("mime_extension_mismatch", "attachment", "medium", 10,
                att.filename + ": uzantı ." + ext + " ama MIME " + att.content_type,
                "Uzantı ile gerçek dosya türü uyuşmuyor — gizleme taktiği."))
    return out
