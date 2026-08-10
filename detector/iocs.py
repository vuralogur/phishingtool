"""IOC extraction - turn an analyzed mail into blocklist / SIEM feed material.

Static like the rest of the tool: nothing here resolves, fetches or executes
anything. Every value is text that was already parsed out of the message.

Two output conventions:

  * TEXT output is DEFANGED (``hxxp://``, ``[.]``, ``[at]``) so an analyst can
    paste it into a ticket or a chat window without a stray click.
  * JSON / CSV keep RAW values - a machine is the consumer there and defanging
    would only have to be undone.
"""
from __future__ import annotations
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field

from .util import domain_of_address, is_ip, registered_domain

# Same shape as the parser's URL regex: stop at whitespace, quotes and brackets.
_URL_RE = re.compile(r"""https?://[^\s"'<>)\]]+""", re.IGNORECASE)
# URLs sitting in an attribute value (href=, src=, action=, content="0;url=…")
# or a redirect parameter. Anything after "=" is a destination the mail points
# at, unlike a URL that is merely displayed as anchor text.
_ATTR_URL_RE = re.compile(r"""(?i)=\s*["']?\s*(https?://[^\s"'<>)\]]+)""")
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_SCHEME_RE = re.compile(r"(?i)\bhttp(s?)://")
_HOST_RE = re.compile(r"(?i)^https?://(?:[^/@]*@)?([^/:?#]+)")


@dataclass
class IOCSet:
    """Deduplicated, sorted indicators pulled out of one message."""
    urls: list = field(default_factory=list)
    domains: list = field(default_factory=list)      # hosts + registrable domains
    ips: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    attachments: list = field(default_factory=list)  # filename/type/size/sha256

    def is_empty(self) -> bool:
        return not (self.urls or self.domains or self.ips or self.emails
                    or self.attachments)

    def to_dict(self) -> dict:
        return {
            "urls": self.urls,
            "domains": self.domains,
            "ips": self.ips,
            "emails": self.emails,
            "attachments": self.attachments,
        }


def defang(value: str) -> str:
    """http://evil.tk -> hxxp://evil[.]tk: unclickable, trivially reversible."""
    out = _SCHEME_RE.sub(lambda m: "hxxp" + m.group(1) + "://", value or "")
    return out.replace(".", "[.]").replace("@", "[at]")


def collect(email) -> IOCSet:
    """Extract every observable an analyst could feed to a blocklist."""
    urls, hosts, ips, addrs = set(), set(), set(), set()

    # Anchor hrefs plus a sweep for form actions, image sources, meta-refresh
    # and redirect targets - destinations the parser's link list does not hold.
    for href in _all_urls(email):
        urls.add(href)
        host = _host_of(href)
        if not host:
            continue
        if is_ip(host):
            ips.add(host)
        else:
            hosts.add(host)

    for addr in (getattr(email, "from_addr", ""), getattr(email, "reply_to", ""),
                 getattr(email, "return_path", "")):
        addr = (addr or "").strip().lower()
        if "@" in addr:
            addrs.add(addr)
            hosts.add(domain_of_address(addr))

    origin = _origin_ip(email)
    if origin:
        ips.add(origin)

    # Both the exact host and its registrable domain: one blocks the sender's
    # infrastructure, the other blocks the whole domain they registered.
    domains = set()
    for host in hosts:
        if not host:
            continue
        domains.add(host)
        rdom = registered_domain(host)
        if rdom:
            domains.add(rdom)

    return IOCSet(
        urls=sorted(urls),
        domains=sorted(domains),
        ips=sorted(ips),
        emails=sorted(addrs),
        attachments=[_attachment(a) for a in getattr(email, "attachments", []) or []],
    )


def _all_urls(email) -> set:
    out = set()
    for link in getattr(email, "links", []) or []:
        href = (getattr(link, "href", "") or "").strip()
        if href.lower().startswith(("http://", "https://")):
            out.add(href)
    # In HTML only attribute values count: a URL shown as anchor *text* is what
    # the attacker wants the eye to read (usually the real brand), not where the
    # mail leads - feeding it to a blocklist would block the victim's own bank.
    out.update(m.strip() for m in _ATTR_URL_RE.findall(getattr(email, "html_body", "") or ""))
    out.update(m.strip() for m in _URL_RE.findall(getattr(email, "text_body", "") or ""))
    return {u for u in out if u}


def _host_of(url: str) -> str:
    m = _HOST_RE.match(url or "")
    return m.group(1).strip().lower().rstrip(".") if m else ""


def _origin_ip(email) -> str:
    """First public IP in the oldest Received line - where the mail entered."""
    for line in reversed(getattr(email, "received", []) or []):
        for candidate in _IPV4_RE.findall(line):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not (ip.is_private or ip.is_loopback or ip.is_reserved
                    or ip.is_multicast):
                return str(ip)
    return ""


def _attachment(att) -> dict:
    payload = getattr(att, "payload", b"") or b""
    return {
        "filename": getattr(att, "filename", "") or "",
        "content_type": getattr(att, "content_type", "") or "",
        "size": getattr(att, "size", 0),
        "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
    }
