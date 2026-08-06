"""Shared helpers: domain parsing, IP detection, edit distance."""
from __future__ import annotations
import re

# tldextract gives correct registrable-domain handling (e.g. co.uk domains).
# Configure it to NEVER fetch the public-suffix list over the network — it
# ships a bundled snapshot, keeping us offline-safe. If the package is missing
# we fall back to a naive last-two-labels heuristic.
try:  # pragma: no cover - import guard
    import tldextract  # type: ignore
    _extract = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover
    _extract = None

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_ip(host: str) -> bool:
    return bool(_IP_RE.match((host or "").strip()))


def registered_domain(host: str) -> str:
    """Registrable domain: a.b.example.co.uk -> example.co.uk.

    IPs are returned unchanged. Falls back to the last two labels when
    tldextract is unavailable.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if is_ip(host):
        return host
    if _extract is not None:
        ext = _extract(host)
        if ext.domain and ext.suffix:
            return ext.domain + "." + ext.suffix
        return ext.domain or host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def domain_of_address(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().lower().rstrip(".")


def has_non_ascii(s: str) -> bool:
    return any(ord(c) > 127 for c in s)


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance — used for look-alike domain detection."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
