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

# Public suffixes used by looks_like_domain() when tldextract is unavailable.
# Not a substitute for the PSL — just enough to tell "paypal.com" from "Ltd.Sti".
_FALLBACK_SUFFIXES = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "io", "co", "me", "tv", "cc", "app", "dev", "online", "site", "shop",
    "store", "xyz", "top", "live", "click", "link", "zip", "mov", "tk", "ml",
    "ga", "cf", "gq", "pw", "su", "icu", "buzz", "cyou",
    "tr", "de", "fr", "nl", "uk", "ru", "it", "es", "pl", "se", "no", "fi",
    "dk", "eu", "ch", "at", "be", "cz", "gr", "pt", "ro", "hu", "ie", "il",
    "us", "ca", "au", "nz", "jp", "cn", "kr", "in", "br", "mx", "ar", "za",
    "ua", "ae", "sa", "az", "kz", "bg", "rs", "hr", "sk", "si", "lt", "lv",
}

# Turkish letters that a dictionary entry and the mail may spell differently.
# str.lower() maps "I" to "i" and never to "ı", so "VAKIFBANK".lower() can never
# equal "vakıfbank" — folding BOTH sides is the only comparison that works.
_FOLD = str.maketrans({
    "ı": "i", "İ": "i", "I": "i", "ş": "s", "Ş": "s", "ğ": "g", "Ğ": "g",
    "ü": "u", "Ü": "u", "ö": "o", "Ö": "o", "ç": "c", "Ç": "c",
    "â": "a", "Â": "a", "î": "i", "Î": "i", "û": "u", "Û": "u",
})


def is_ip(host: str) -> bool:
    return bool(_IP_RE.match((host or "").strip()))


def ascii_fold(s: str) -> str:
    """Turkish text -> lowercase ASCII skeleton, for comparison only.

    "ACİLEN", "acilen" and "acılen" all fold to "acilen", so an ALL-CAPS subject
    line (which phishing loves) matches the same keyword a lowercase one does.
    Never use the result as output — evidence must quote what the mail said.
    """
    return (s or "").translate(_FOLD).lower()


def looks_like_domain(token: str) -> bool:
    """True when the token's last label is a real public suffix.

    The domain regex used on display names and anchor text happily matches
    "Kargo Ltd.Sti" — treating that as somebody's domain produced a hard,
    18-point spoofing indicator on perfectly ordinary corporate mail.
    """
    token = (token or "").strip().lower().rstrip(".")
    if "." not in token:
        return False
    if _extract is not None:
        return bool(_extract(token).suffix)
    return token.rsplit(".", 1)[-1] in _FALLBACK_SUFFIXES


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


def lookalike_distance(candidate: str, legit: str) -> int:
    """Edit distance when ``candidate`` is a plausible typosquat of ``legit``, 0 otherwise.

    The allowance has to scale with the brand's own name. Two edits away from
    "fb.com" is half the internet — vb.com, gb.com and eb.com all scored a hard
    16-point "look-alike domain" — while two edits away from "garantibbva.com.tr"
    really is a typosquat. Names under three characters get no allowance at all.
    """
    if not candidate or not legit or candidate == legit:
        return 0
    sld = legit.split(".")[0]
    if len(sld) < 3:
        return 0
    limit = 1 if len(sld) <= 6 else 2
    distance = levenshtein(candidate, legit)
    return distance if distance <= limit else 0


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
