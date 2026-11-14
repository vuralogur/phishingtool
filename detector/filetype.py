"""What a file IS, read from its leading bytes - not what its name or MIME says.

An attachment makes two claims about itself, a filename and a Content-Type, and
the sender writes both. The first bytes are the one part of the claim that the
program eventually opening the file cannot be talked out of: a PE image named
``fatura.pdf`` is still a PE image.

Pure byte comparison against well-known signatures. Nothing is opened,
decompressed or executed, and an unrecognised file is reported as unknown
(``""``) rather than guessed at - callers treat "unknown" as "no finding".
"""
from __future__ import annotations
import re

# Kind -> how the report names it.
LABELS = {
    "exe": "çalıştırılabilir dosya",
    "ole": "eski Office/OLE belgesi",
    "zip": "ZIP arşivi",
    "archive": "arşiv/disk imajı",
    "image": "resim",
    "pdf": "PDF",
    "rtf": "RTF belgesi",
    "html": "HTML sayfası",
    "svg": "SVG",
}

_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_MACHO = {bytes.fromhex(h) for h in
          ("feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe")}
_HEIF_BRANDS = (b"heic", b"heix", b"hevc", b"mif1", b"msf1", b"avif")
_MARKUP = re.compile(rb"\s*(<!doctype\s+html|<html|<head|<body|<script|<svg|<\?xml)",
                     re.IGNORECASE)


def _is_pe(data: bytes) -> bool:
    """A DOS/PE executable. "MZ" alone is two letters; ask for the rest."""
    if data[:2] != b"MZ" or len(data) < 64:
        return False
    offset = int.from_bytes(data[60:64], "little")
    if data[offset:offset + 4] == b"PE\x00\x00":
        return True
    stub = data[:1024]
    return b"This program cannot be run" in stub or b"This program must be run" in stub


def _is_image(data: bytes) -> bool:
    return (data[:8] == b"\x89PNG\r\n\x1a\n"
            or data[:3] == b"\xff\xd8\xff"
            or data[:6] in (b"GIF87a", b"GIF89a")
            or (data[:4] == b"RIFF" and data[8:12] == b"WEBP")
            or data[:4] in (b"II*\x00", b"MM\x00*")
            or (data[:2] == b"BM" and data[6:10] == b"\x00\x00\x00\x00"
                and len(data) > 26)
            or (data[4:8] == b"ftyp" and data[8:12] in _HEIF_BRANDS))


def _is_archive(data: bytes) -> bool:
    return (data[:6] == b"Rar!\x1a\x07"
            or data[:6] == b"7z\xbc\xaf\x27\x1c"
            or data[:3] == b"\x1f\x8b\x08"
            or data[:4] == b"MSCF"
            or data[:3] == b"BZh"
            or data[:6] == b"\xfd7zXZ\x00"
            or data[32769:32774] == b"CD001")       # ISO 9660


def _markup(data: bytes) -> str:
    head = data[:2048]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        head = head.decode("utf-16", "replace").encode("utf-8", "replace")
    elif head[:3] == b"\xef\xbb\xbf":
        head = head[3:]
    m = _MARKUP.match(head)
    if not m:
        return ""
    tag = m.group(1).lower()
    if tag == b"<svg":
        return "svg"
    if tag == b"<?xml":
        # XML can be anything; only an SVG root makes it a page a browser runs.
        return "svg" if b"<svg" in head.lower() else ""
    return "html"


def sniff(data: bytes) -> str:
    """The kind of file these bytes are: a key of ``LABELS``, or ``""``.

    Ordered from the signatures that are hardest to fake by accident to the
    loosest (a "%PDF-" marker may sit anywhere in the first kilobyte, and HTML
    has no magic number at all).
    """
    if not data:
        return ""
    if (_is_pe(data) or data[:4] == b"\x7fELF" or data[:4] in _MACHO
            or (data[:4] == b"L\x00\x00\x00" and data[4:20] == _LNK_CLSID)):
        return "exe"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if _is_image(data):
        return "image"
    if _is_archive(data):
        return "archive"
    if data[:5] == b"{\\rtf":
        return "rtf"
    if b"%PDF-" in data[:1024]:
        return "pdf"
    return _markup(data)
