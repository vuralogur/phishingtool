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
from ..util import (CONFUSABLES as _CONFUSABLES, ascii_fold, domain_of_address,
                    link_origin, registered_domain, is_ip)

_REDIRECT_PARAMS = {"url", "redirect", "redir", "next", "return", "returnurl",
                    "dest", "destination", "continue", "goto", "target", "u", "r"}


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


def _made_of(word: str, vocab) -> bool:
    """True when ``word`` splits completely into vocabulary words (securelogin)."""
    reach = [True] + [False] * len(word)
    for end in range(1, len(word) + 1):
        reach[end] = any(reach[start] and word[start:end] in vocab
                         for start in range(end))
    return reach[-1]


def _combosquat(label: str, brand: str, lures) -> str:
    """The lure words glued to ``brand`` in a domain label, "" if there are none.

    "Brand plus anything" used to be enough, and it flagged the brands' own
    infrastructure (googleapis, amazonaws, paypalobjects, githubusercontent) and
    plain words that happen to contain a brand (pineapple, applebees, zoominfo).
    What makes a combosquat a combosquat is the second half: a word chosen to
    look like the brand's login or support desk - paypal-secure, garanti-destek,
    akbankgiris. So everything in the label that is not the brand has to be made
    of lure words; digits around them are ignored (secure24).
    """
    if len(brand) < 4 or label == brand or not lures:
        return ""
    start = label.find(brand)
    while start >= 0:
        rest = label[:start] + "-" + label[start + len(brand):]
        words = [w for w in (chunk.strip("0123456789")
                             for chunk in re.split(r"[^a-z0-9]+", rest)) if w]
        if words and all(_made_of(w, lures) for w in words):
            return ", ".join(words)
        start = label.find(brand, start + 1)
    return ""


def run(email, online=False, ctx=None):
    ctx = ctx or {}
    brands = ctx.get("brands", {})
    from_rdom = ctx.get("from_rdom", "")
    # Folded like the brand tokens: a dictionary line may be written "şifre".
    lures = {ascii_fold(w) for w in ctx.get("lure_words", ())}
    out = []
    seen = set()

    def add(ind):
        if ind.id not in seen:
            out.append(ind)
            seen.add(ind.id)

    def brand_checks(host, rdom, sld, sub, where=""):
        """Does this host dress itself up as a known brand? (link or sender)"""
        for brand, domains in brands.items():
            if rdom in domains:
                continue  # the real thing
            # Host labels are ASCII; a dictionary entry spelled "vakıfbank" can
            # only ever match one after folding (see util.ascii_fold).
            token = ascii_fold(brand)
            extra = _combosquat(sld, token, lures)
            if extra:
                add(Indicator("combosquat_domain", "url", "high", 16,
                    where + "'" + brand + "' + tuzak kelime (" + extra + ") domainde: " + rdom,
                    "Marka adini giris/destek/guvenlik gibi bir kelimeyle birlestiren "
                    "sahte domain (combosquatting)."))
            if sub and re.search(r"(^|[^a-z0-9])" + re.escape(token) + r"([^a-z0-9]|$)", sub):
                add(Indicator("brand_in_subdomain", "url", "high", 16,
                    where + "'" + brand + "' subdomain'e gomulu, gercek domain: " + rdom,
                    "Marka adi subdomain'e konup alakasiz bir domain mesru gosteriliyor."))

        # IDN / homoglyph confusable mapping to a brand
        if "xn--" in host or any(ord(c) > 127 for c in host):
            skel = _skeleton(_idna_decode(host))
            skel_rdom = registered_domain(skel)
            for brand, domains in brands.items():
                if skel_rdom in domains and rdom not in domains:
                    add(Indicator("confusable_brand", "url", "high", 18,
                        where + host + " benzer karakterlerle '" + skel_rdom + "' gibi gorunuyor",
                        "Unicode/IDN homoglyph ile marka domaini taklit ediliyor."))
                    break

    # Every brand domain in one alternation, longest first so "paypal.com.tr"
    # is not cut short at "paypal.com".
    owner = {d: domains for domains in brands.values() for d in domains}
    in_path = re.compile(
        r"(?:^|[/.@_-])(" + "|".join(re.escape(d) for d in
                                     sorted(owner, key=len, reverse=True))
        + r")(?=[/._-]|$)") if owner else None

    def parts(host):
        rdom = registered_domain(host)
        sld = rdom.split(".")[0] if rdom else host
        sub = host[:-len(rdom)].rstrip(".") if rdom and host.endswith(rdom) else ""
        return rdom, sld, sub

    for link in email.links:
        href = link.href
        host = _host(href)
        if not host or is_ip(host):
            continue
        rdom, sld, sub = parts(host)
        where = link_origin(link)
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
                        where + host + " acik yonlendirme: parametre '" + key + "' baska URL tasiyor",
                        "Guvenilir domain, kurbani parametredeki adrese yonlendirmek icin kullaniliyor."))
                    break

        brand_checks(host, rdom, sld, sub, where)

        # --- a brand's domain written into the PATH of somebody else's host ---
        # evil.example/paypal.com/login: the eye finds "paypal.com" in the
        # address and stops reading. Query strings are left to open_redirect.
        if in_path and not first_party:
            try:
                path = urlparse(href).path.lower()
            except Exception:
                path = ""
            m = in_path.search(path)
            if m and rdom not in owner[m.group(1)]:
                add(Indicator("brand_in_path", "url", "medium", 10,
                    where + "'" + m.group(1) + "' adresin yolunda geciyor, gercek host: " + host,
                    "Marka domaini URL'nin yol kismina yazilmis; baglantinin gittigi "
                    "yer bastaki host'tur. Arsiv/onbellek servisleri de boyle adres "
                    "uretir, bu yuzden tek basina kanit degildir."))

        # --- DGA / random-looking host label ---
        # The digit cap keeps numeric infrastructure labels (cdn-000123456789,
        # customer ids) out: those are high-entropy and vowel-poor by nature but
        # are not generated domains.
        mostly_digits = sum(c.isdigit() for c in sld) > len(sld) // 2
        if not first_party and not mostly_digits and len(sld) >= 12 and _entropy(sld) >= 3.6:
            vowels = sum(c in "aeiou" for c in sld)
            if vowels / len(sld) < 0.3:
                add(Indicator("random_host", "url", "low", 6,
                    where + "Rastgele/algoritmik gorunumlu host: " + sld,
                    "Yuksek entropili, sesli harfsiz host adlari DGA/tek kullanimlik phishing altyapisina isaret eder."))

    # The sender's own domain gets the same brand questions as a link. A mail
    # from noreply@paypal-secure.com that links nowhere suspicious was invisible
    # to every check above. Runs after the links and shares their de-duplication,
    # so a domain used as both sender and link target is one finding, not two.
    for label, addr in (("Gonderen (From) domaini: ", getattr(email, "from_addr", "")),
                        ("Reply-To domaini: ", getattr(email, "reply_to", ""))):
        host = domain_of_address(addr or "")
        if host and not is_ip(host):
            brand_checks(host, *parts(host), where=label)

    return out
