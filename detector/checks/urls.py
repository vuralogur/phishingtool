"""URL / link checks: anchor-href mismatch, homograph, IP hosts, shorteners, TLDs."""
from __future__ import annotations
import re
from urllib.parse import urlparse

from ..indicators import Indicator
from ..util import registered_domain, is_ip, has_non_ascii, levenshtein

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "t.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

_DOMAIN_TOKEN = re.compile(r"[\w-]+\.\w{2,}")


def _host(href):
    try:
        return (urlparse(href).hostname or "").lower()
    except Exception:
        return ""


def _authority(href):
    # portion between scheme:// and the first '/'
    rest = href.split("://", 1)[-1]
    return rest.split("/", 1)[0]


def run(email, online=False, ctx=None):
    ctx = ctx or {}
    brands = ctx.get("brands", {})
    sus_tlds = ctx.get("suspicious_tlds", set())
    out = []
    seen = set()

    def add(ind):
        if ind.id not in seen:
            out.append(ind)
            seen.add(ind.id)

    for link in email.links:
        host = _host(link.href)
        if not host:
            continue
        rdom = registered_domain(host)

        # Anchor text implies one domain, href points somewhere else.
        m = _DOMAIN_TOKEN.search((link.text or "").lower())
        if m:
            text_dom = registered_domain(m.group(0))
            if text_dom and rdom and text_dom != rdom:
                from_rdom = ctx.get("from_rdom", "")
                authed = ctx.get("auth_level") == "pass"
                first_party = bool(from_rdom) and rdom == from_rdom
                shows_own = bool(from_rdom) and text_dom == from_rdom
                # Legit click-trackers route the sender's own links through a
                # tracking (sub)domain. Suppress when the href is first-party, or
                # when an authenticated sender shows its own domain as anchor
                # text. Still fire when the text names a *different* brand.
                if not first_party and not (shows_own and authed):
                    add(Indicator("anchor_href_mismatch", "url", "high", 20,
                        "metin '" + m.group(0) + "' -> gercek hedef " + host,
                        "Gorunen link ile tiklaninca gidilen adres farkli - klasik phishing."))

        if is_ip(host):
            add(Indicator("ip_url", "url", "high", 14,
                "Baglanti dogrudan IP adresi: " + host,
                "Mesru kurumlar linklerde ciplak IP kullanmaz."))
        if "xn--" in host:
            add(Indicator("punycode_domain", "url", "medium", 12,
                "Punycode/IDN domain: " + host,
                "Punycode ile taninmis marka taklidi (homograph) yapilabilir."))
        elif has_non_ascii(host):
            add(Indicator("homograph_domain", "url", "high", 18,
                "Domainde ASCII olmayan karakter: " + host,
                "Latin disi benzer karakterlerle marka taklidi."))
        if "@" in _authority(link.href):
            add(Indicator("at_in_url", "url", "medium", 10,
                "URL yetki kisminda '@': " + link.href,
                "'@' oncesi kisim yok sayilir; gercek host gizlenir."))
        if rdom in SHORTENERS:
            add(Indicator("url_shortener", "url", "medium", 8,
                "URL kisaltici: " + rdom,
                "Kisaltici gercek hedefi gizler."))
        tld = rdom.rsplit(".", 1)[-1] if "." in rdom else ""
        if tld and tld in sus_tlds:
            add(Indicator("suspicious_tld", "url", "medium", 8,
                "Supheli TLD: ." + tld + " (" + host + ")",
                "Ucretsiz/kotuye kullanilan TLD'ler phishing'de sik gorulur."))
        if host.count(".") >= 4:
            add(Indicator("excessive_subdomains", "url", "low", 6,
                "Asiri subdomain: " + host,
                "Marka adini subdomain'e gomerek mesru gosterme taktigi."))

        # Look-alike of a known brand (edit distance 1-2, not the real domain).
        for brand, domains in brands.items():
            for legit in domains:
                d = levenshtein(rdom, legit)
                if 0 < d <= 2 and rdom not in domains:
                    add(Indicator("lookalike_domain", "url", "high", 16,
                        host + " ~ " + legit + " (fark " + str(d) + ")",
                        "'" + legit + "' markasina cok benzeyen sahte domain."))
    return out
