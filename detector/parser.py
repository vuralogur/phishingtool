"""Parse a .eml / .msg file or raw email text into a normalized ParsedEmail."""
from __future__ import annotations
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
import re

from . import msg as _msg
from .util import domain_of_address

_URL_RE = re.compile(r"""https?://[^\s"'<>)\]]+""", re.IGNORECASE)

# The mail files this parser accepts - one list so a folder scan (batch, bench)
# and the parser can never disagree about what counts as a mail.
MAIL_GLOBS = ("*.eml", "*.msg")


@dataclass
class Link:
    text: str
    href: str


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    payload: bytes = b""  # decoded content, kept for deep static analysis

    @property
    def ext(self) -> str:
        name = self.filename or ""
        return name.rsplit(".", 1)[-1].lower() if "." in name else ""


@dataclass
class ParsedEmail:
    raw: str
    raw_bytes: bytes
    headers: dict
    from_display: str
    from_addr: str
    from_domain: str
    reply_to: str
    return_path: str
    to: str
    subject: str
    date: str
    received: list
    auth_results: list
    text_body: str
    html_body: str
    links: list
    attachments: list
    # Provenance: "eml" is a raw RFC 822 file, "msg" came out of an Outlook
    # container. header_source says whether the headers are the real internet
    # headers ("rfc822") or were rebuilt from MAPI properties ("mapi") - in the
    # latter case SPF/DKIM/DMARC and Received are absent from the file itself.
    source_format: str = "eml"
    header_source: str = "rfc822"
    # Received-SPF is a different header with a different grammar ("Pass (...)",
    # not "spf=pass"), so it is kept apart from auth_results instead of being
    # appended to it - mixed together, neither could be read correctly.
    spf_received: list = field(default_factory=list)


class _AnchorExtractor(HTMLParser):
    """Collect (href, visible_text) pairs from <a> tags."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self._href = href
                self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []


def _extract_links(html: str, text: str) -> list:
    links = []
    if html:
        p = _AnchorExtractor()
        try:
            p.feed(html)
        except Exception:
            pass
        for href, atext in p.links:
            if href.lower().startswith(("http://", "https://")):
                links.append(Link(text=atext, href=href))
    seen = {l.href for l in links}
    for m in _URL_RE.findall(text or ""):
        if m not in seen:
            links.append(Link(text="", href=m))
            seen.add(m)
    return links


def _headers_map(msg) -> dict:
    out = {}
    for k, v in msg.items():
        out.setdefault(k.lower(), []).append(str(v))
    return out


def _first_addr(value: str):
    disp, addr = parseaddr(value or "")
    return disp, addr


def _bodies(msg):
    text_body, html_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            if (part.get_content_disposition() or "") == "attachment":
                continue
            ctype = part.get_content_type()
            try:
                content = part.get_content()
            except Exception:
                raw = part.get_payload(decode=True) or b""
                content = raw.decode("utf-8", "replace")
            if isinstance(content, bytes):
                content = content.decode("utf-8", "replace")
            if ctype == "text/plain" and not text_body:
                text_body = content
            elif ctype == "text/html" and not html_body:
                html_body = content
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = msg.get_payload(decode=False)
        if isinstance(content, bytes):
            content = content.decode("utf-8", "replace")
        content = content or ""
        if ctype == "text/html":
            html_body = content
        else:
            text_body = content
    return text_body, html_body


def _attachments(msg):
    out = []
    if not msg.is_multipart():
        return out
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if (part.get_content_disposition() or "") == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            out.append(Attachment(
                filename=filename or "(unnamed)",
                content_type=part.get_content_type(),
                size=len(payload),
                payload=payload,
            ))
    return out


def _build(msg, raw: str, raw_bytes: bytes,
           source_format: str = "eml", header_source: str = "rfc822") -> ParsedEmail:
    from_disp, from_addr = _first_addr(msg.get("From", ""))
    _, reply_to = _first_addr(msg.get("Reply-To", ""))
    _, return_path = _first_addr(msg.get("Return-Path", ""))
    received = [str(r) for r in (msg.get_all("Received", []) or [])]
    auth = [str(x) for x in (msg.get_all("Authentication-Results", []) or [])]
    spf_received = [str(x) for x in (msg.get_all("Received-SPF", []) or [])]
    text_body, html_body = _bodies(msg)
    return ParsedEmail(
        raw=raw,
        raw_bytes=raw_bytes,
        headers=_headers_map(msg),
        from_display=from_disp,
        from_addr=from_addr,
        from_domain=domain_of_address(from_addr),
        reply_to=reply_to,
        return_path=return_path,
        to=str(msg.get("To", "") or ""),
        subject=str(msg.get("Subject", "") or ""),
        date=str(msg.get("Date", "") or ""),
        received=received,
        auth_results=auth,
        spf_received=spf_received,
        text_body=text_body,
        html_body=html_body,
        links=_extract_links(html_body, text_body),
        attachments=_attachments(msg),
        source_format=source_format,
        header_source=header_source,
    )


def parse_bytes(raw: bytes) -> ParsedEmail:
    # An Outlook .msg is an OLE2 container, not RFC 822 text: convert it first so
    # every check downstream keeps seeing one shape of email.
    if _msg.is_msg(raw):
        message, header_source = _msg.to_message(raw)
        rebuilt = message.as_bytes()
        return _build(message, rebuilt.decode("utf-8", "replace"), rebuilt,
                      source_format="msg", header_source=header_source)
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return _build(msg, raw.decode("utf-8", "replace"), raw)


def parse_text(raw: str) -> ParsedEmail:
    msg = Parser(policy=policy.default).parsestr(raw)
    return _build(msg, raw, raw.encode("utf-8", "replace"))


def parse_file(path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
