"""Received-chain forensics: turn the header stack into a readable route.

Every mail carries the servers it travelled through in ``Received`` headers,
newest first. The tool already parsed them - ``auth_verify`` only pulls the
originating IP out and drops the rest. This module turns the whole chain into
structured hops so a report can *show* the route instead of hiding it.

Static like everything else here:

* **No DNS of any kind.** The reverse name compared against the announced HELO
  name is the one the receiving MTA already wrote into the header. Nothing is
  resolved, fetched or connected to.
* **No scoring.** Hops are metadata, exactly like the ATT&CK labels: they
  explain a verdict, they never change it.

Trust caveat that belongs with any such table: only the hops added *above* the
first server you actually trust mean anything. Everything below it can be
invented by the sender, so the chain is evidence, not proof.
"""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime

from .util import registered_domain

# Clause keywords of the Received grammar (RFC 5321 §4.4). The lookbehind keeps
# "mailfrom" / "gateway-by" from being read as a clause start.
_KEYWORD_RE = re.compile(r"(?i)(?<![\w.\-=])(from|by|with|via|id|for)\s+")
_HEADER_RE = re.compile(r"(?i)^received:\s*")
_BRACKET_RE = re.compile(r"\[([^\]]+)\]")
_IPV6_PREFIX_RE = re.compile(r"(?i)^ipv6:")
_HELO_RE = re.compile(r"(?i)\bhelo[=\s]+([^\s()]+)")
_COMMENT_TAIL_RE = re.compile(r"\s*\([^)]*\)\s*$")
_TLS_RE = re.compile(r"(?i)\b(tls|ssl|cipher)\b")

# Protocols that imply the hop was encrypted (RFC 3848 and its dialects).
_TLS_PROTOCOLS = frozenset({"esmtps", "esmtpsa", "smtps", "https", "utf8esmtps",
                            "utf8esmtpsa"})
# Anything longer than this between two hops is worth pointing at: mail that
# sat somewhere is mail that may have been handled somewhere.
BIG_DELAY = 300


@dataclass
class Hop:
    """One Received line, oldest first (``index`` 1 is where the mail entered)."""
    index: int = 0
    from_host: str = ""     # name the sender announced (HELO/EHLO) - a claim
    from_rdns: str = ""     # reverse name the receiving MTA wrote down
    from_ip: str = ""
    by_host: str = ""
    protocol: str = ""      # ESMTP, ESMTPS, SMTP, local ...
    tls: bool = False
    for_addr: str = ""
    time: object = None     # datetime | None
    delay: object = None    # seconds since the previous hop | None
    flags: list = field(default_factory=list)
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "from_host": self.from_host,
            "from_rdns": self.from_rdns,
            "from_ip": self.from_ip,
            "by_host": self.by_host,
            "protocol": self.protocol,
            "tls": self.tls,
            "for": self.for_addr,
            "time": self.time.isoformat() if self.time is not None else "",
            "delay": self.delay,
            "flags": list(self.flags),
            "raw": self.raw,
        }


def parse(email) -> list:
    """Received headers -> hops in travel order (oldest first).

    A malformed line never raises: it comes back as a hop that carries only its
    raw text and an ``unparsed`` flag, because a line we cannot read is still a
    hop the mail went through.
    """
    lines = list(getattr(email, "received", []) or [])
    hops = [_hop(line, i) for i, line in enumerate(reversed(lines), 1)]
    _link(hops)
    return hops


def summary(hops) -> dict:
    """Chain in one glance: hop count, entry IP, total time, flags raised."""
    hops = list(hops or [])
    origin = ""
    for hop in hops:
        if hop.from_ip and not _is_private(hop.from_ip):
            origin = hop.from_ip
            break
    stamped = [h.time for h in hops if h.time is not None]
    span = _delta(stamped[-1], stamped[0]) if len(stamped) > 1 else None
    return {
        "count": len(hops),
        "origin_ip": origin,
        "span": span,
        "flags": sorted({f for hop in hops for f in hop.flags}),
    }


# ---------- one line ----------
def _hop(line, index: int) -> Hop:
    raw = _HEADER_RE.sub("", " ".join(str(line or "").split()))
    body, stamp = _split_date(raw)
    hop = Hop(index=index, raw=raw, time=stamp)
    parts = _clauses(body)
    hop.from_host, hop.from_rdns, hop.from_ip = _origin(parts.get("from", ""))
    hop.by_host = _host_token(parts.get("by", ""))
    hop.protocol = _first_token(parts.get("with", "")) or _first_token(parts.get("via", ""))
    hop.tls = (hop.protocol.lower() in _TLS_PROTOCOLS) or bool(_TLS_RE.search(raw))
    hop.for_addr = _address(parts.get("for", ""))
    if not (hop.from_host or hop.from_ip or hop.by_host):
        hop.flags.append("unparsed")
    _flag(hop)
    return hop


def _split_date(text: str):
    """Split off the timestamp after the last top-level ';' (parens excluded)."""
    cut, depth = -1, 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == ";" and depth == 0:
            cut = i
    if cut < 0:
        return text, None
    return text[:cut], _time(text[cut + 1:])


def _time(text: str):
    text = (text or "").strip()
    for candidate in (text, _COMMENT_TAIL_RE.sub("", text)):
        if not candidate:
            continue
        try:
            return parsedate_to_datetime(candidate)
        except (TypeError, ValueError):
            continue
    return None


def _depths(text: str) -> list:
    """Parenthesis depth at every character, so clauses inside comments are skipped."""
    out, depth = [], 0
    for ch in text:
        out.append(depth)
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
    return out


def _clauses(text: str) -> dict:
    depth = _depths(text)
    marks = [m for m in _KEYWORD_RE.finditer(text) if depth[m.start()] == 0]
    out = {}
    for n, m in enumerate(marks):
        end = marks[n + 1].start() if n + 1 < len(marks) else len(text)
        out.setdefault(m.group(1).lower(), text[m.end():end].strip())
    return out


def _origin(clause: str):
    """'mail.x (rdns.y [1.2.3.4])' -> announced name, reverse name, IP."""
    if not clause:
        return "", "", ""
    outside, inside = _split_comment(clause)
    host = _host_token(outside)
    ip = _find_ip(clause)
    if _as_ip(host) or host in ("unknown", "localhost.localdomain"):
        host = ""             # "from [1.2.3.4]" / "from unknown" announce nothing
    rdns = ""
    helo = _HELO_RE.search(inside)
    if helo:
        # Exim style: "from unknown ([1.2.3.4] helo=mail.x)". The name inside is
        # the sender's claim, not a reverse lookup - do not compare it to itself.
        host = host or _clean_host(helo.group(1))
    for token in inside.split():
        cand = _clean_host(token)
        if not cand or "." not in cand or "=" in token or _as_ip(cand):
            continue
        if helo and cand == _clean_host(helo.group(1)):
            continue
        rdns = cand
        break
    return host, rdns, ip


def _split_comment(clause: str):
    """Text outside parentheses, and everything that was inside them."""
    outside, inside, depth = [], [], 0
    for ch in clause:
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            inside.append(" ")
            continue
        (inside if depth else outside).append(ch)
    return "".join(outside).strip(), "".join(inside).strip()


def _tokens(text: str) -> list:
    return [t for t in (text or "").split() if t]


def _first_token(text: str) -> str:
    tokens = _tokens(_split_comment(text or "")[0])
    return tokens[0].strip(",;") if tokens else ""


def _host_token(text: str) -> str:
    return _clean_host(_first_token(text))


def _clean_host(token: str) -> str:
    return (token or "").strip().strip("[]()<>,;").rstrip(".").lower()


def _address(text: str) -> str:
    token = _first_token(text)
    return token.strip("<>,;").lower()


def _as_ip(token: str) -> str:
    """Return the normalized address if the token is one, '' otherwise."""
    token = _IPV6_PREFIX_RE.sub("", (token or "").strip().strip("[]()<>,;"))
    if token.count(":") == 1 and "." in token:   # 1.2.3.4:25
        token = token.split(":")[0]
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return ""


def _find_ip(text: str) -> str:
    for m in _BRACKET_RE.finditer(text):
        ip = _as_ip(m.group(1))
        if ip:
            return ip
    for token in _tokens(text):
        ip = _as_ip(token)
        if ip:
            return ip
    return ""


def _ip_object(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_private(value: str) -> bool:
    ip = _ip_object(value)
    return ip is not None and (ip.is_private or ip.is_loopback or ip.is_reserved
                               or ip.is_link_local)


def _flag(hop: Hop):
    private = _is_private(hop.from_ip)
    if private:
        hop.flags.append("private_ip")
    if hop.from_host and hop.from_rdns and (
            registered_domain(hop.from_host) != registered_domain(hop.from_rdns)):
        hop.flags.append("rdns_mismatch")
    # Only judge encryption on real internet hops: "with local" between two
    # processes on one box is not a plaintext delivery over the wire.
    if hop.protocol and not hop.tls and hop.from_ip and not private:
        hop.flags.append("no_tls")


def _link(hops: list):
    """Fill in per-hop delays once the whole chain is known."""
    previous = None
    for hop in hops:
        if hop.time is None:
            continue
        delta = _delta(hop.time, previous)
        if delta is not None:
            hop.delay = int(round(delta))
            if hop.delay > BIG_DELAY:
                hop.flags.append("big_delay")
            elif hop.delay < 0:
                hop.flags.append("clock_skew")
        previous = hop.time


def _delta(now, before):
    """Seconds between two timestamps, or None if they cannot be compared."""
    if now is None or before is None:
        return None
    if (now.tzinfo is None) != (before.tzinfo is None):
        return None            # naive vs aware: any number would be a guess
    return (now - before).total_seconds()
