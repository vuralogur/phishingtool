"""Reading the STRUCTURE of container attachments - never running their payload.

Three containers hide what a byte scan of the attachment cannot see:

* a ZIP's file list - ``fatura.pdf.exe`` inside ``fatura.zip``;
* an OOXML document's relationship files - the remote template a .docx pulls
  in when opened, and the hyperlinks behind its text;
* a PDF's object streams - where modern writers keep the link annotations and
  the ``/JavaScript`` names, deflated.

What this module does, and all it does:

* the ZIP central directory is read (names, sizes, the "encrypted" flag); no
  member is extracted;
* of an OOXML package only ``*.rels`` files are inflated - a few kilobytes of
  XML each - and only in memory;
* of a PDF only streams declared ``/Type /ObjStm`` are inflated, in memory.

Nothing is written to disk, nothing is handed to another program, nothing is
executed or rendered, and every read is capped (see the ``MAX_*`` constants) so
a decompression bomb costs a bounded amount of memory and then stops. A file
that cannot be read this way yields "nothing found", never an exception.
"""
from __future__ import annotations
import html
import io
import re
import zipfile
import zlib
from dataclasses import dataclass
from functools import lru_cache

MAX_MEMBERS = 5000                 # zip entries listed
MAX_RELS = 64                      # *.rels files read per package
MAX_RELS_BYTES = 512 * 1024        # per .rels file, inflated
MAX_OBJSTMS = 400                  # PDF object streams inflated
MAX_OBJSTM_BYTES = 4 * 1024 * 1024    # per stream, inflated
MAX_PDF_BYTES = 32 * 1024 * 1024      # all streams of one PDF together
MAX_URLS = 300


@dataclass(frozen=True)
class Member:
    name: str
    encrypted: bool
    size: int


def markup_text(data: bytes) -> str:
    """Attachment bytes as markup text; a wrong guess only costs some accents."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


# -- ZIP ---------------------------------------------------------------------


def _open_zip(data: bytes):
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return None


@lru_cache(maxsize=8)
def zip_members(data: bytes):
    """The files a ZIP says it holds, or ``None`` if it is not a readable ZIP.

    Central directory only. File names are not hidden by ZIP encryption, so a
    password-protected archive still lists what is inside it.
    """
    zf = _open_zip(data)
    if zf is None:
        return None
    try:
        with zf:
            return tuple(Member(i.filename, bool(i.flag_bits & 0x1), i.file_size)
                         for i in zf.infolist()[:MAX_MEMBERS] if not i.is_dir())
    except Exception:
        return None


def is_office_package(members) -> bool:
    """OOXML (docx/xlsx/pptx) or OpenDocument: a document that is a ZIP inside."""
    names = [m.name for m in members or ()]
    return "[Content_Types].xml" in names or (bool(names) and names[0] == "mimetype")


# -- OOXML -------------------------------------------------------------------

_REL = re.compile(rb"<Relationship\b[^>]*>", re.IGNORECASE)


def _attr(tag: bytes, name: bytes) -> str:
    m = re.search(rb"\b" + name + rb"""\s*=\s*(["'])(.*?)\1""", tag,
                  re.IGNORECASE | re.DOTALL)
    return html.unescape(m.group(2).decode("utf-8", "replace")).strip() if m else ""


@lru_cache(maxsize=8)
def ooxml_external(data: bytes) -> tuple:
    """``(kind, target)`` for every relationship pointing OUTSIDE the package.

    ``kind`` is the last segment of the relationship type, lowercased:
    ``hyperlink``, ``attachedtemplate``, ``oleobject``, ``frame``, ``image``...
    """
    zf = _open_zip(data)
    if zf is None:
        return ()
    out = []
    try:
        with zf:
            infos = zf.infolist()
            if not any(i.filename == "[Content_Types].xml" for i in infos):
                return ()
            rels = [i for i in infos if i.filename.lower().endswith(".rels")]
            for info in rels[:MAX_RELS]:
                if info.file_size > MAX_RELS_BYTES:
                    continue
                try:
                    with zf.open(info) as fh:
                        xml = fh.read(MAX_RELS_BYTES)
                except Exception:
                    continue          # encrypted, corrupt, unsupported method
                for tag in _REL.findall(xml):
                    if _attr(tag, b"TargetMode").lower() != "external":
                        continue
                    kind = _attr(tag, b"Type").rsplit("/", 1)[-1].lower()
                    target = _attr(tag, b"Target")
                    if kind and target:
                        out.append((kind, target))
    except Exception:
        pass
    return tuple(out)


# -- PDF ---------------------------------------------------------------------

_STREAM = re.compile(rb"stream\r?\n")
_URI = re.compile(rb"/URI\s*\(((?:\\.|[^\\()]){4,2048})\)", re.DOTALL)
_URI_HEX = re.compile(rb"/URI\s*<([0-9A-Fa-f\s]{8,4096})>")
_PDF_ESCAPE = re.compile(rb"\\(\r\n|[\s\S])")


@lru_cache(maxsize=8)
def pdf_object_streams(data: bytes) -> bytes:
    """The inflated contents of a PDF's ``/ObjStm`` streams, joined.

    Since PDF 1.5 a writer may pack ordinary objects - annotations, actions,
    the catalog - into deflated object streams, where a scan of the raw file
    finds neither ``/URI`` nor ``/JavaScript``. Page content, images and fonts
    are other stream types and are left alone.
    """
    out, total, count = [], 0, 0
    for m in _STREAM.finditer(data):
        # The dictionary describing this stream sits right before the keyword.
        head = data[max(0, m.start() - 2048):m.start()]
        cut = head.rfind(b"obj")
        if cut >= 0:
            head = head[cut:]
        if b"/ObjStm" not in head or b"/FlateDecode" not in head:
            continue
        end = data.find(b"endstream", m.end())
        if end < 0:
            continue
        count += 1
        if count > MAX_OBJSTMS or total >= MAX_PDF_BYTES:
            break
        try:
            chunk = zlib.decompressobj().decompress(data[m.end():end], MAX_OBJSTM_BYTES)
        except Exception:
            continue                  # encrypted PDF, or not deflate after all
        out.append(chunk)
        total += len(chunk)
    return b"\n".join(out)


def _pdf_string(raw: bytes) -> str:
    raw = _PDF_ESCAPE.sub(lambda m: m.group(1) if m.group(1) in (b"(", b")", b"\\") else b"",
                          raw)
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", "replace").strip()
    return raw.decode("latin-1").strip()


def pdf_urls(data: bytes) -> list:
    """Every ``/URI`` action target in the PDF - plain objects and object streams.

    Raw strings exactly as the file spells them; the caller decides which are
    web links. In an encrypted PDF they come out as noise and match nothing.
    """
    found, seen = [], set()
    for blob in (data, pdf_object_streams(data)):
        if not blob:
            continue
        values = [_pdf_string(m.group(1)) for m in _URI.finditer(blob)]
        for m in _URI_HEX.finditer(blob):
            try:
                values.append(_pdf_string(bytes.fromhex(re.sub(rb"\s+", b"", m.group(1)).decode())))
            except ValueError:
                continue
        for value in values:
            if value and value not in seen:
                seen.add(value)
                found.append(value)
                if len(found) >= MAX_URLS:
                    return found
    return found
