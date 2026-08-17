"""Tier 2 - deeper URL analysis beyond the basic urls.py checks.

  * open_redirect   - a trusted-looking URL whose query smuggles another URL
                      (?url=/redirect=/next=https://...).
  * combosquat      - brand token glued to extra words in the domain label
                      (paypal-secure.com, secure-paypal.net).
  * brand_in_subdomain - brand name buried in a subdomain of an unrelated
                      registrable domain (paypal.login.evil.com).
  * confusable_brand - IDN/Unicode homoglyphs that map to a real brand once
                      punycode is decoded and look-alike chars normalised.
  * random_host     - high-entropy / DGA-looking host label.

All offline string analysis; nothing is fetched (unshortening stays opt-in and
is intentionally NOT done here to avoid any network egress by default).
"""
from __future__ import annotations
import math
import re
from urllib.parse import urlparse, parse_qs

from ..indicators import Indicator
from ..util import ascii_fold, registered_domain, is_ip

_REDIRECT_PARAMS = {"url", "redirect", "redir", "next", "return", "returnurl",
                    "dest", "destination", "continue", "goto", "target", "u", "r"}

# Common homoglyphs -> ASCII skeleton (Cyrillic / Greek / math letters).
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "к": "k", "м": "m",
    "т": "t", "в": "b", "н": "h", "г": "r", "ѐ": "e", "ӏ": "l",
    "ο": "o", "α": "a", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "υ": "u", "χ": "x", "ϲ": "c", "β": "b",
    "ⅰ": "i", "ⅼ": "l", "ｏ": "o", "ａ": "a", "ｅ": "e",
}


def _host(href: str) -> str:
    try:
        return (urlparse(href).hostname or "").lower()
    except Exception:
        return ""


def _idna_decode(host: str) -> str:
    labels = []
    for lab in host.split("."):
        if lab.startswith("xn--"):
            try:
                labels.append(lab[4:].encode("ascii").decode("punycode"))
                continue
            except Exception:
                pass
        labels.append(lab)
    return ".".join(labels)


def _skeleton(s: str) -> str:
    return "".join(_CONFUSABLES.get(c, c) for c in s).lower()


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in
                (s.count(ch) for ch in set(s)))


def _combosquat(label: str, brand: str) -> bool:
    if brand not in label or label == brand or len(brand) < 4:
        return False
    if label.startswith(brand) or label.endswith(brand):
        return True
    return bool(re.search(r"[^a-z0-9]" + re.escape(brand), label)
                or re.search(re.escape(brand) + r"[^a-z0-9]", label))


def run(email, online=False, ctx=None):
    ctx = ctx or {}
    brands = ctx.get("brands", {})
    from_rdom = ctx.get("from_rdom", "")
    out = []
    seen = set()

    def add(ind):
        if ind.id not in seen:
            out.append(ind)
            seen.add(ind.id)

    for link in email.links:
        href = link.href
        host = _host(href)
        if not host or is_ip(host):
            continue
        rdom = registered_domain(host)
        sld = rdom.split(".")[0] if rdom else host
        sub = host[:-len(rdom)].rstrip(".") if rdom and host.endswith(rdom) else ""
        # The sender's own click-tracker / redirect infrastructure - not an attack.
        first_party = bool(from_rdom) and rdom == from_rdom

        # --- open redirect ---
        try:
            qs = parse_qs(urlparse(href).query)
        except Exception:
            qs = {}
        if not first_party:
            for key, vals in qs.items():
                if key.lower() in _REDIRECT_PARAMS and any(re.search(r"https?", v, re.I) or "%3a" in v.lower() for v in vals):
                    add(Indicator("open_redirect", "url", "medium", 10,
                        host + " acik yonlendirme: parametre '" + key + "' baska URL tasiyor",
                        "Guvenilir domain, kurbani parametredeki adrese yonlendirmek icin kullaniliyor."))
                    break

        # --- brand-relative checks ---
        for brand, domains in brands.items():
            if rdom in domains:
                continue  # the real thing
            # Host labels are ASCII; a dictionary entry spelled "vakıfbank" can
            # only ever match one after folding (see util.ascii_fold).
            token = ascii_fold(brand)
            if _combosquat(sld, token):
                add(Indicator("combosquat_domain", "url", "high", 16,
                    "'" + brand + "' + ek kelime domainde: " + rdom,
                    "Marka adini fazladan kelimeyle birlestiren sahte domain (combosquatting)."))
            if sub and re.search(r"(^|[^a-z0-9])" + re.escape(token) + r"([^a-z0-9]|$)", sub):
                add(Indicator("brand_in_subdomain", "url", "high", 16,
                    "'" + brand + "' subdomain'e gomulu, gercek domain: " + rdom,
                    "Marka adi subdomain'e konup alakasiz bir domain mesru gosteriliyor."))

        # --- IDN / homoglyph confusable mapping to a brand ---
        if "xn--" in host or any(ord(c) > 127 for c in host):
            skel = _skeleton(_idna_decode(host))
            skel_rdom = registered_domain(skel)
            for brand, domains in brands.items():
                if skel_rdom in domains and rdom not in domains:
                    add(Indicator("confusable_brand", "url", "high", 18,
                        host + " benzer karakterlerle '" + skel_rdom + "' gibi gorunuyor",
                        "Unicode/IDN homoglyph ile marka domaini taklit ediliyor."))
                    break

        # --- DGA / random-looking host label ---
        # The digit cap keeps numeric infrastructure labels (cdn-000123456789,
        # customer ids) out: those are high-entropy and vowel-poor by nature but
        # are not generated domains.
        mostly_digits = sum(c.isdigit() for c in sld) > len(sld) // 2
        if not first_party and not mostly_digits and len(sld) >= 12 and _entropy(sld) >= 3.6:
            vowels = sum(c in "aeiou" for c in sld)
            if vowels / len(sld) < 0.3:
                add(Indicator("random_host", "url", "low", 6,
                    "Rastgele/algoritmik gorunumlu host: " + sld,
                    "Yuksek entropili, sesli harfsiz host adlari DGA/tek kullanimlik phishing altyapisina isaret eder."))

    return out
