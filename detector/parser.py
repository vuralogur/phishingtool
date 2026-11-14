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
from .util import domain_of_address, looks_like_domain, strip_url_noise

_URL_RE = re.compile(r"""https?://[^\s"'<>)\]]+""", re.IGNORECASE)
# A URL typed without a scheme ("www.x.com", "x.com/login"). Mail clients turn
# these into clickable links, so leaving the scheme off must not hide a link.
# The lookbehind keeps it from firing inside an address (user@x.com) or in the
# middle of another token; _text_urls() then decides whether it is really a URL.
_BARE_URL_RE = re.compile(
    r"""(?<![\w@./:\\-])((?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?(?:/[^\s"'<>)\]]*)?)""",
    re.IGNORECASE,
)
# "https:" followed by any run of slashes or backslashes - browsers accept every
# spelling ("https:\\x", "https:/x", "https:x") as the same absolute URL.
_WEB_SCHEME_RE = re.compile(r"^(https?):[\\/]*", re.IGNORECASE)
# Scheme-relative: "//x.com/login" (and its backslash spellings).
_RELATIVE_SCHEME_RE = re.compile(r"^[\\/]{2,}")
_CODE_SCHEMES = ("javascript:", "vbscript:")

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


class _LinkExtractor(HTMLParser):
    """Collect every place the HTML can send a click, plus the loose text.

    ``links`` holds (target, visible_text) pairs: <a href> with its anchor text,
    and <area href>, <form action>, <button/input formaction> with no text.
    ``loose`` is the visible text *outside* anchors - a URL typed there is
    auto-linked by the mail client. Anchor text is deliberately not part of it:
    that is what the sender wants the eye to read, not where the click goes.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.loose = []
        self._href = None
        self._text = []
        self._skip = 0      # inside <script>/<style>: not text the reader sees

    def finish(self):
        """Close the anchor in progress - an <a> never closed is still a link."""
        if self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attr = {k: (v or "") for k, v in attrs}
        if tag == "a":
            self.finish()
            if attr.get("href"):
                self._href = attr["href"]
        elif tag == "area" and attr.get("href"):
            self.links.append((attr["href"], ""))
        elif tag == "form" and attr.get("action"):
            self.links.append((attr["action"], ""))
        elif tag in ("button", "input") and attr.get("formaction"):
            self.links.append((attr["formaction"], ""))
        elif tag in ("script", "style"):
            self._skip += 1

    def handle_data(self, data):
        if self._skip:
            return
        if self._href is not None:
            self._text.append(data)
        else:
            self.loose.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "a":
            self.finish()
        elif tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)


def normalize_href(href: str) -> str:
    """An href as the browser resolves it, or "" when it is not a web link.

    Only "http://..." used to count, so every other spelling a browser happily
    follows was invisible to the URL checks: a leading space, "//host/path",
    "https:\\\\host", "https:/host". They all come back as scheme://host/path.
    """
    h = strip_url_noise(href)
    m = _WEB_SCHEME_RE.match(h)
    if m:
        scheme = m.group(1).lower()
    else:
        m = _RELATIVE_SCHEME_RE.match(h)
        if not m:
            return ""
        # No page to inherit a scheme from inside a mail; clients assume https.
        scheme = "https"
    rest = h[m.end():]
    # Backslashes are path separators to a browser - but only before the query.
    cut = min([i for i in (rest.find("?"), rest.find("#")) if i >= 0] or [len(rest)])
    rest = rest[:cut].replace("\\", "/") + rest[cut:]
    return scheme + "://" + rest if rest else ""


def _text_urls(text: str) -> list:
    """URLs written in running text, with or without a scheme."""
    text = text or ""
    out = list(_URL_RE.findall(text))
    # Blank the full URLs out first, so "?next=www.x.com/a" inside one of them is
    # not counted again as a second link.
    for m in _BARE_URL_RE.finditer(_URL_RE.sub(" ", text)):
        token = m.group(1).rstrip(".,;:!?")
        host = token.split("/", 1)[0].split(":", 1)[0]
        # "Ltd.Sti" and "rapor.pdf" fit the pattern too. Require what makes a
        # client link it: a real public suffix, and either "www." or a path.
        if not (token.lower().startswith("www.") or "/" in token):
            continue
        if looks_like_domain(host):
            out.append("http://" + token)
    return out


def _extract_links(html: str, text: str) -> list:
    links = []
    loose = [text or ""]
    if html:
        p = _LinkExtractor()
        try:
            p.feed(html)
            p.close()
        except Exception:
            pass
        p.finish()
        for href, atext in p.links:
            web = normalize_href(href)
            if web:
                links.append(Link(text=atext, href=web))
            elif strip_url_noise(href).lower().startswith(_CODE_SCHEMES):
                # javascript:location='http://...' - the destination is inside
                # the code; pull it out so the URL checks can judge it.
                for inner in _URL_RE.findall(href):
                    links.append(Link(text=atext, href=inner))
        loose.append(" ".join(p.loose))
    seen = {l.href for l in links}
    for chunk in loose:
        for url in _text_urls(chunk):
            if url not in seen:
                links.append(Link(text="", href=url))
                seen.add(url)
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
    """Every text/plain and text/html body part, joined - not just the first.

    A client renders the LAST part it understands, so a mail with a harmless
    HTML part followed by the real one showed the reader a login form while the
    analyzer read the decoy. Joining the parts means every check (links, forms,
    wording, IOCs) sees all the markup the mail carries, whichever part a given
    client picks.
    """
    texts, htmls = [], []
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
            if ctype == "text/plain":
                texts.append(content)
            elif ctype == "text/html":
                htmls.append(content)
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
            htmls.append(content)
        else:
            texts.append(content)
    return "\n".join(texts), "\n".join(htmls)


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
