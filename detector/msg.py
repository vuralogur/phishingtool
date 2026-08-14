"""Read an Outlook .msg (OLE2 / CFB container) with the standard library only.

Why a hand-written reader instead of ``extract_msg``: the analysis core of this
tool is pure stdlib, and an optional dependency would mean the .msg path silently
becomes "not supported" on whichever machine forgot to install it. A .msg is a
Compound File Binary (MS-CFB) holding MAPI properties (MS-OXMSG), and everything
the pipeline needs - the internet headers, the bodies, the attachment bytes - is
a plain stream inside that container.

Nothing here executes or resolves anything: streams are read as bytes and mapped
onto an ``email.message.EmailMessage``, so no check downstream can tell a .msg
from a .eml.

Header fidelity has exactly two cases, and the caller is told which one it got:

* ``PR_TRANSPORT_MESSAGE_HEADERS`` present -> the original RFC 822 headers were
  saved with the mail, so Received / Authentication-Results / DKIM-Signature are
  the real thing and every check runs at full strength (``"rfc822"``).
* absent -> headers are rebuilt from MAPI properties: sender, recipients,
  subject, submit time. Identity, URL, content and attachment checks all work;
  SPF/DKIM/DMARC and the Received chain do not exist *in the file* at all, so
  they are reported as unverifiable instead of being invented (``"mapi"``).

References: MS-CFB (container), MS-OXMSG (.msg layout), MS-OXPROPS (property ids).
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage
from email.parser import Parser
from email.utils import format_datetime, formataddr
import struct

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_ENDOFCHAIN = 0xFFFFFFFE
_MAXREGSECT = 0xFFFFFFFA  # anything above this is a sentinel, not a sector

_SUBSTG = "__substg1.0_"
_PROPS = "__properties_version1.0"
_ATTACH = "__attach_version1.0"
_RECIP = "__recip_version1.0"

# Property ids we read (MS-OXPROPS). Kept as names so the mapping below stays
# readable - a bare "0x5D02" tells the next reader nothing.
_TRANSPORT_HEADERS = "007D"
_SUBJECT = "0037"
_BODY = "1000"
_BODY_HTML = "1013"
_MESSAGE_ID = "1035"
_SENDER_NAME = "0C1A"
_SENDER_EMAIL = "0C1F"
_SENDER_SMTP = "5D01"
_REPR_NAME = "0042"
_REPR_EMAIL = "0065"
_REPR_SMTP = "5D02"
_REPLY_NAMES = "0050"
_DISPLAY_TO = "0E04"
_DISPLAY_CC = "0E03"
_RECIP_NAME = "3001"
_RECIP_EMAIL = "3003"
_RECIP_SMTP = "39FE"
_ATTACH_LONG_NAME = "3707"
_ATTACH_NAME = "3704"
_ATTACH_DATA = "3701"
_ATTACH_MIME = "370E"

# Fixed-size properties live in __properties_version1.0, tag + type together.
_TAG_SUBMIT_TIME = "00390040"
_TAG_DELIVERY_TIME = "0E060040"
_TAG_RECIP_TYPE = "0C150003"
_TAG_INTERNET_CPID = "3FDE0003"
_TAG_MESSAGE_CODEPAGE = "3FFD0003"

# Belong to the MIME body we build ourselves; taking them from the saved
# transport headers would describe a body that is no longer there.
_SKIP_HEADERS = {"content-type", "content-transfer-encoding", "mime-version",
                 "content-disposition", "content-id"}


class MsgError(ValueError):
    """The bytes are not a readable .msg / CFB container."""


def is_msg(data: bytes) -> bool:
    """True if these bytes start with the OLE2/CFB magic a .msg always has."""
    return data[:8] == SIGNATURE


@dataclass
class _Dir:
    """One CFB directory entry (a storage, a stream, or the root)."""
    idx: int
    name: str
    kind: int  # 1 = storage, 2 = stream, 5 = root
    left: int
    right: int
    child: int
    start: int
    size: int


class _Cfb:
    """Minimal read-only MS-CFB reader: directory tree in, stream bytes out."""

    def __init__(self, data: bytes):
        if len(data) < 512 or not is_msg(data):
            raise MsgError("OLE2/CFB imzasi yok - bu bir .msg dosyasi degil")
        self._data = data
        shift, mini_shift = struct.unpack_from("<HH", data, 30)
        if not 7 <= shift <= 20 or not 2 <= mini_shift <= shift:
            raise MsgError("CFB sektor boyutu gecersiz")
        self.sector = 1 << shift
        self.mini_sector = 1 << mini_shift
        (n_fat, dir_start, _txn, self.cutoff,
         mini_start, n_mini, difat_start, n_difat) = struct.unpack_from("<8I", data, 44)

        self._fat = self._read_fat(n_fat, difat_start, n_difat)
        self.entries = self._read_dir(dir_start)
        # Small streams are packed into one "mini stream" held by the root entry
        # and chained through their own FAT.
        self._minifat = []
        if n_mini and mini_start <= _MAXREGSECT:
            raw = self._read_big(mini_start, n_mini * self.sector)
            self._minifat = list(struct.unpack_from("<%dI" % (len(raw) // 4), raw))
        root = self.entries[0]
        self._ministream = self._read_big(root.start, root.size) if root.size else b""

    # -- sector plumbing ---------------------------------------------------

    def _off(self, sector: int) -> int:
        off = (sector + 1) * self.sector
        if sector > _MAXREGSECT or off + self.sector > len(self._data):
            raise MsgError("CFB sektoru dosya disina isaret ediyor")
        return off

    def _read_fat(self, n_fat: int, difat_start: int, n_difat: int) -> list:
        difat = list(struct.unpack_from("<109I", self._data, 76))
        per = self.sector // 4 - 1
        sect, seen = difat_start, set()
        while sect <= _MAXREGSECT and len(seen) <= n_difat:
            if sect in seen:
                raise MsgError("CFB DIFAT zinciri donuyor")
            seen.add(sect)
            off = self._off(sect)
            difat += struct.unpack_from("<%dI" % per, self._data, off)
            (sect,) = struct.unpack_from("<I", self._data, off + self.sector - 4)
        fat = []
        for s in difat[:n_fat]:
            if s > _MAXREGSECT:
                continue
            fat += struct.unpack_from("<%dI" % (self.sector // 4), self._data, self._off(s))
        return fat

    def _chain(self, start: int, fat: list) -> list:
        """Sector numbers of one stream, guarded against loops and bad links."""
        out, seen, s = [], set(), start
        while s <= _MAXREGSECT:
            if s in seen or s >= len(fat):
                raise MsgError("CFB sektor zinciri bozuk")
            seen.add(s)
            out.append(s)
            s = fat[s]
        return out

    def _read_big(self, start: int, size: int) -> bytes:
        buf = bytearray()
        for s in self._chain(start, self._fat):
            off = self._off(s)
            buf += self._data[off:off + self.sector]
            if len(buf) >= size:
                break
        return bytes(buf[:size])

    def _read_mini(self, start: int, size: int) -> bytes:
        buf, seen, s = bytearray(), set(), start
        while s <= _MAXREGSECT and len(buf) < size:
            if s in seen or s >= len(self._minifat):
                raise MsgError("CFB mini-sektor zinciri bozuk")
            seen.add(s)
            off = s * self.mini_sector
            buf += self._ministream[off:off + self.mini_sector]
            s = self._minifat[s]
        return bytes(buf[:size])

    def _read_dir(self, dir_start: int) -> list:
        raw = b"".join(self._data[self._off(s):self._off(s) + self.sector]
                       for s in self._chain(dir_start, self._fat))
        out = []
        for i in range(len(raw) // 128):
            b = raw[i * 128:(i + 1) * 128]
            (nlen,) = struct.unpack_from("<H", b, 64)
            name = b[:max(0, min(nlen, 64) - 2)].decode("utf-16-le", "replace")
            left, right, child = struct.unpack_from("<3I", b, 68)
            start, lo, hi = struct.unpack_from("<3I", b, 116)
            # Version 3 (512-byte sectors) leaves the high half of the size
            # undefined, so only a v4 file is allowed to use it.
            size = lo if self.sector == 512 else lo | (hi << 32)
            out.append(_Dir(i, name, b[66], left, right, child, start, size))
        if not out or out[0].kind != 5:
            raise MsgError("CFB kok dizini bulunamadi")
        return out

    # -- public surface ----------------------------------------------------

    def children(self, idx: int) -> list:
        """Entries directly under one storage (the red-black tree, walked flat)."""
        out, stack, seen = [], [self.entries[idx].child], set()
        while stack:
            i = stack.pop()
            if i > _MAXREGSECT or i >= len(self.entries) or i in seen:
                continue
            seen.add(i)
            e = self.entries[i]
            out.append(e)
            stack += [e.left, e.right]
        return out

    def read(self, entry: _Dir) -> bytes:
        if entry.kind != 2 or not entry.size:
            return b""
        if entry.size < self.cutoff:
            return self._read_mini(entry.start, entry.size)
        return self._read_big(entry.start, entry.size)


# -- MAPI property layer ---------------------------------------------------


def _codec(cpid: int) -> str:
    known = {65001: "utf-8", 1200: "utf-16-le", 28591: "latin-1",
             28599: "iso-8859-9", 20127: "ascii", 0: "cp1252"}
    return known.get(cpid) or ("cp%d" % cpid)


def _decode8(raw: bytes, cpid: int) -> str:
    """Decode an 8-bit MAPI string using the message codepage, then fall back."""
    for codec in (_codec(cpid), "cp1252"):
        try:
            return raw.decode(codec)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("cp1252", "replace")


def _text(value, cpid: int) -> str:
    if isinstance(value, bytes):
        value = _decode8(value, cpid)
    return (value or "").replace("\x00", "").strip()


def _long(raw) -> int:
    return struct.unpack_from("<I", raw)[0] if raw and len(raw) >= 4 else 0


def _filetime(raw) -> "datetime | None":
    if not raw or len(raw) < 8:
        return None
    (ft,) = struct.unpack_from("<Q", raw)
    if not ft or ft > 2 ** 62:
        return None
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)


def _props(cfb: _Cfb, idx: int, cpid: int) -> dict:
    """``__substg1.0_*`` streams of one storage -> ``{property id: str | bytes}``.

    A property can be stored unicode (001F), 8-bit (001E) or binary (0102); the
    unicode form wins when a producer wrote both.
    """
    raw = {}
    for e in cfb.children(idx):
        if e.kind == 2 and e.name.startswith(_SUBSTG):
            tag = e.name[len(_SUBSTG):][:8].upper()
            if len(tag) == 8:
                raw[tag] = cfb.read(e)
    out = {}
    for want in ("001F", "001E", "0102"):
        for tag, val in raw.items():
            pid, ptype = tag[:4], tag[4:]
            if ptype != want or pid in out:
                continue
            if want == "001F":
                out[pid] = val.decode("utf-16-le", "replace")
            elif want == "001E":
                out[pid] = _decode8(val, cpid)
            else:
                out[pid] = val
    return out


def _fixed(cfb: _Cfb, idx: int, header: int) -> dict:
    """``__properties_version1.0`` -> ``{tag: 8 value bytes}`` for fixed-size props.

    ``header`` is the leading block size: 32 for the top-level message, 8 for an
    attachment or recipient storage (MS-OXMSG 2.4).
    """
    stream = next((e for e in cfb.children(idx)
                   if e.kind == 2 and e.name == _PROPS), None)
    if stream is None:
        return {}
    raw = cfb.read(stream)
    out = {}
    for off in range(header, len(raw) - 15, 16):
        (tag,) = struct.unpack_from("<I", raw, off)
        out["%08X" % tag] = raw[off + 8:off + 16]
    return out


def _smtp(value) -> str:
    """Keep an address only if it really is one - Exchange stores legacy DNs here."""
    return value if isinstance(value, str) and "@" in value else ""


def _attachments(cfb: _Cfb, cpid: int) -> list:
    out = []
    for e in cfb.children(0):
        if e.kind != 1 or not e.name.startswith(_ATTACH):
            continue
        p = _props(cfb, e.idx, cpid)
        data = p.get(_ATTACH_DATA)
        if not isinstance(data, bytes):
            # An embedded message is a storage, not a stream: no bytes to hand
            # to the attachment checks, so skip it rather than fake an empty one.
            continue
        name = _text(p.get(_ATTACH_LONG_NAME) or p.get(_ATTACH_NAME), cpid)
        mime = _text(p.get(_ATTACH_MIME), cpid).split(";")[0].strip().lower()
        out.append((name or "(unnamed)", mime, data))
    return out


def _recipients(cfb: _Cfb, cpid: int) -> tuple:
    to, cc = [], []
    for e in cfb.children(0):
        if e.kind != 1 or not e.name.startswith(_RECIP):
            continue
        p = _props(cfb, e.idx, cpid)
        addr = _smtp(p.get(_RECIP_SMTP)) or _smtp(p.get(_RECIP_EMAIL))
        name = _text(p.get(_RECIP_NAME), cpid)
        who = formataddr((name, addr)) if addr else name
        if not who:
            continue
        kind = _long(_fixed(cfb, e.idx, 8).get(_TAG_RECIP_TYPE))
        (cc if kind == 2 else to).append(who)  # 1 = To, 2 = Cc, 3 = Bcc
    return to, cc


def _mapi_headers(cfb: _Cfb, p: dict, fixed: dict, cpid: int) -> dict:
    """Rebuild RFC 822 headers from MAPI properties, best effort, no invention."""
    disp = _text(p.get(_REPR_NAME) or p.get(_SENDER_NAME), cpid)
    addr = (_smtp(p.get(_REPR_SMTP)) or _smtp(p.get(_REPR_EMAIL))
            or _smtp(p.get(_SENDER_SMTP)) or _smtp(p.get(_SENDER_EMAIL)))
    sender = _smtp(p.get(_SENDER_SMTP)) or _smtp(p.get(_SENDER_EMAIL))
    to, cc = _recipients(cfb, cpid)
    when = _filetime(fixed.get(_TAG_SUBMIT_TIME)) or _filetime(fixed.get(_TAG_DELIVERY_TIME))
    reply = _text(p.get(_REPLY_NAMES), cpid)

    out = {
        "From": formataddr((disp, addr)) if addr else disp,
        # "on behalf of": the account that actually sent it differs from the
        # identity shown as From - keep both, the mismatch is evidence.
        "Sender": (formataddr((_text(p.get(_SENDER_NAME), cpid), sender))
                   if sender and sender != addr else ""),
        "Reply-To": reply if "@" in reply else "",
        "To": ", ".join(to) or _text(p.get(_DISPLAY_TO), cpid),
        "Cc": ", ".join(cc) or _text(p.get(_DISPLAY_CC), cpid),
        "Subject": _text(p.get(_SUBJECT), cpid),
        "Date": format_datetime(when) if when else "",
        "Message-ID": _text(p.get(_MESSAGE_ID), cpid),
    }
    return {k: v for k, v in out.items() if v}


def to_message(data: bytes) -> tuple:
    """``.msg`` bytes -> ``(EmailMessage, header_source)``.

    ``header_source`` is ``"rfc822"`` when the saved internet headers were used
    and ``"mapi"`` when they were absent and had to be rebuilt from properties.
    """
    cfb = _Cfb(data)
    fixed = _fixed(cfb, 0, 32)
    cpid = _long(fixed.get(_TAG_INTERNET_CPID)) or _long(fixed.get(_TAG_MESSAGE_CODEPAGE))
    p = _props(cfb, 0, cpid)

    text = _text(p.get(_BODY), cpid)
    html = _text(p.get(_BODY_HTML), cpid)

    msg = EmailMessage()
    if text and html:
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")
    elif html:
        msg.set_content(html, subtype="html")
    else:
        msg.set_content(text)

    for name, mime, blob in _attachments(cfb, cpid):
        maintype, _, subtype = mime.partition("/")
        if maintype == "text":
            msg.add_attachment(_decode8(blob, cpid), subtype=subtype or "plain",
                               filename=name)
        else:
            msg.add_attachment(blob, maintype=maintype or "application",
                               subtype=subtype or "octet-stream", filename=name)

    transport = _text(p.get(_TRANSPORT_HEADERS), cpid)
    source = "rfc822" if transport else "mapi"
    if transport:
        saved = Parser(policy=policy.default).parsestr(transport, headersonly=True)
        for k, v in saved.items():
            if k.lower() not in _SKIP_HEADERS:
                msg[k] = v
    # Fills everything when there were no transport headers, and only the gaps
    # when there were.
    for k, v in _mapi_headers(cfb, p, fixed, cpid).items():
        if k not in msg:
            msg[k] = v
    return msg, source
