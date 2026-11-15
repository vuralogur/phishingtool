"""Shared helpers: domain parsing, IP detection, edit distance."""
from __future__ import annotations
import ipaddress
import re
import unicodedata

# tldextract gives correct registrable-domain handling (e.g. co.uk domains).
# Configure it to NEVER fetch the public-suffix list over the network — it
# ships a bundled snapshot, keeping us offline-safe. If the package is missing
# we fall back to a naive last-two-labels heuristic.
try:  # pragma: no cover - import guard
    import tldextract  # type: ignore
    _extract = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover
    _extract = None

# One part of a dotted IPv4 host as a browser reads it (WHATWG URL, "IPv4 number
# parser"): 0x.. is hex, a leading 0 is octal, anything else is decimal.
_HEX_PART = re.compile(r"0x([0-9a-f]*)")
_OCT_PART = re.compile(r"0[0-7]+")
_DEC_PART = re.compile(r"[0-9]+")

# Characters a browser throws away before it parses a URL attribute: leading and
# trailing C0 controls / spaces, and tabs or newlines anywhere inside.
_C0_AND_SPACE = "".join(chr(c) for c in range(0x21))
_TAB_OR_NEWLINE = re.compile(r"[\t\r\n]")

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


def strip_url_noise(value: str) -> str:
    """A URL attribute with the padding a browser ignores removed.

    ``href=" https://x"`` and ``href="ht\\ntps://x"`` both open https://x, so a
    check that compares the raw attribute against "https://" sees no link where
    the reader sees one.
    """
    return _TAB_OR_NEWLINE.sub("", value or "").strip(_C0_AND_SPACE)


def _ipv4_part(part: str):
    """One dotted part -> its number, or None when it is not a number at all."""
    m = _HEX_PART.fullmatch(part)
    if m:
        return int(m.group(1) or "0", 16)
    if len(part) > 1 and part[0] == "0":
        # A leading zero commits the part to octal: "08" is an error, not 8.
        return int(part, 8) if _OCT_PART.fullmatch(part) else None
    if _DEC_PART.fullmatch(part):
        return int(part)
    return None


def canonical_ip(host: str) -> str:
    """The address a URL host really is, in plain notation; "" if it is a name.

    A browser accepts far more than "192.168.1.1" as an IPv4 host: one decimal
    number (3232235777), hex (0xC0A80101), octal (0300.0250.01.01), fewer than
    four parts (192.168.257) and any mix of those. All of them open the same
    address, and all of them slipped past a dotted-quad regex - which is exactly
    why they are used. IPv6 literals ("[2001:db8::1]") are recognised too.
    """
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return ""
    if ":" in host:
        try:
            return str(ipaddress.ip_address(host.split("%", 1)[0]))
        except ValueError:
            return ""
    parts = host.split(".")
    if len(parts) > 4:
        return ""
    numbers = [_ipv4_part(p) for p in parts]
    if any(n is None for n in numbers):
        return ""
    *head, last = numbers
    # Every part but the last is one byte; the last one fills whatever is left.
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return ""
    value = last
    for position, n in enumerate(head):
        value += n << (8 * (3 - position))
    return str(ipaddress.IPv4Address(value))


# Letters from other scripts that render like Latin ones (Cyrillic / Greek /
# Roman-numeral forms). Lowercase only: skeleton() lowercases before it looks.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "к": "k", "м": "m",
    "т": "t", "в": "b", "н": "h", "г": "r", "ѐ": "e", "ӏ": "l",
    "ο": "o", "α": "a", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "υ": "u", "χ": "x", "ϲ": "c", "β": "b",
    "ⅰ": "i", "ⅼ": "l", "ｏ": "o", "ａ": "a", "ｅ": "e",
}

# Characters that take up no space on screen: zero-width spaces and joiners,
# direction marks and overrides, the soft hyphen, the BOM.
_INVISIBLE = re.compile(
    "[­͏؜᠎​-‏‪-‮⁠-⁤"
    "⁦-⁯﻿]")


def strip_invisible(s: str) -> str:
    """Drop characters that take up no space on screen (see ``_INVISIBLE``)."""
    return _INVISIBLE.sub("", s or "")


def link_origin(link) -> str:
    """Evidence prefix for a link that was found inside an attachment.

    Without it a finding names an address the reader cannot find anywhere in
    the mail body - because it is in the PDF.
    """
    source = getattr(link, "source", "")
    return "Ek '" + source + "' icindeki link - " if source else ""


def clean_filename(name: str) -> str:
    """A file name as the operating system will treat it.

    Windows drops trailing dots and spaces - "fatura.exe." is saved and run as
    fatura.exe - and zero-width or direction-override characters are invisible
    to the reader but would otherwise sit inside the "extension".
    """
    return strip_invisible(name or "").rstrip(". \t")


def file_ext(name: str) -> str:
    """Lowercase extension of a file name or archive path ("" when none)."""
    base = clean_filename(name).replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].strip().lower() if "." in base else ""


def skeleton(s: str) -> str:
    """What a string LOOKS like, as lowercase ASCII - for comparison only.

    "PаyPal" with a Cyrillic "а", "Pay\\u200bPal" with a zero-width space and
    "𝐏𝐚𝐲𝐏𝐚𝐥" in mathematical bold all read "PayPal" to a person and all three
    fail a plain string comparison - which is why they are written that way.
    This folds compatibility forms (NFKC), drops invisible characters and maps
    look-alike letters, so the comparison sees what the eye sees.
    """
    s = _INVISIBLE.sub("", unicodedata.normalize("NFKC", s or ""))
    return "".join(CONFUSABLES.get(c, c) for c in ascii_fold(s))


def is_ip(host: str) -> bool:
    """True for any host a browser would treat as an address (see canonical_ip)."""
    return bool(canonical_ip(host))


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
