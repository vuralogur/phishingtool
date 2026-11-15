"""URL / link checks: anchor-href mismatch, homograph, IP hosts, shorteners, TLDs."""
from __future__ import annotations
import re
from urllib.parse import urlparse

from ..indicators import Indicator
from ..util import (canonical_ip, domain_of_address, has_non_ascii, link_origin,
                    looks_like_domain, lookalike_distance, registered_domain)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "t.ly", "shorturl.at", "rb.gy", "tiny.cc",
    "s.id", "shrtco.de", "clck.ru", "surl.li", "trib.al", "lnkd.in",
    "bl.ink", "short.io", "shorturl.com", "urlz.fr", "u.to", "qrco.de",
    "linktr.ee", "cutt.us", "gg.gg", "v.gd", "0rz.tw", "shorte.st",
}

# Whole dotted name, not the first two labels: "www.paypal.com" must not be read
# as "www.paypal", which has no public suffix and would be discarded below.
_DOMAIN_TOKEN = re.compile(r"(?:[\w-]+\.)+[a-z]{2,}")


def _host(href):
    try:
        return (urlparse(href).hostname or "").lower()
    except Exception:
        return ""


def _authority(href):
    # portion between scheme:// and the first '/'
    rest = href.split("://", 1)[-1]
    return rest.split("/", 1)[0]


def _tld_swap(rdom: str, legit: str, sus_tlds) -> bool:
    """Same name, different ending: akbank.net for akbank.com.

    Two limits keep it honest. A country ending is skipped unless it is on the
    suspicious list - amazon.co.uk and google.com.tr are how multinationals
    name their regional sites, not squats. And the name needs four letters:
    "x", "fb" and "ups" exist under every TLD for unrelated reasons.
    """
    name, _, ending = rdom.partition(".")
    legit_name, _, legit_ending = legit.partition(".")
    if name != legit_name or not ending or ending == legit_ending or len(name) < 4:
        return False
    last = ending.rsplit(".", 1)[-1]
    return len(last) >= 3 or last in sus_tlds


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

    def domain_checks(host, rdom, where=""):
        """What the domain itself gives away - asked of links and of the sender."""
        if "xn--" in host:
            add(Indicator("punycode_domain", "url", "medium", 12,
                where + "Punycode/IDN domain: " + host,
                "Punycode ile taninmis marka taklidi (homograph) yapilabilir."))
        elif has_non_ascii(host):
            add(Indicator("homograph_domain", "url", "high", 18,
                where + "Domainde ASCII olmayan karakter: " + host,
                "Latin disi benzer karakterlerle marka taklidi."))
        tld = rdom.rsplit(".", 1)[-1] if "." in rdom else ""
        if tld and tld in sus_tlds:
            add(Indicator("suspicious_tld", "url", "medium", 8,
                where + "Supheli TLD: ." + tld + " (" + host + ")",
                "Ucretsiz/kotuye kullanilan TLD'ler phishing'de sik gorulur."))

        # Look-alike of a known brand (edit distance 1-2, not the real domain).
        for brand, domains in brands.items():
            if rdom in domains:
                continue
            for legit in domains:
                d = lookalike_distance(rdom, legit)
                if d:
                    add(Indicator("lookalike_domain", "url", "high", 16,
                        where + host + " ~ " + legit + " (fark " + str(d) + ")",
                        "'" + legit + "' markasina cok benzeyen sahte domain."))
                if _tld_swap(rdom, legit, sus_tlds):
                    add(Indicator("tld_swap_domain", "url", "medium", 10,
                        where + rdom + " - '" + legit + "' ile ayni ad, farkli uzanti",
                        "Marka adi ayni, uzanti farkli. Markanin kendi yan domaini de "
                        "olabilir (oyleyse brands.txt'ye ekleyin); ayni ad baska "
                        "uzantida kaydedilerek taklit de boyle yapilir."))

    for link in email.links:
        host = _host(link.href)
        if not host:
            continue
        rdom = registered_domain(host)
        where = link_origin(link)

        # Anchor text implies one domain, href points somewhere else.
        # looks_like_domain: anchor text such as "Ltd.Sti" or "dosya.pdf" matches
        # the domain regex without being a domain - comparing it to the href
        # produced a hard 20-point mismatch on ordinary mail.
        m = _DOMAIN_TOKEN.search((link.text or "").lower())
        if m and looks_like_domain(m.group(0)):
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
                        where + "metin '" + m.group(0) + "' -> gercek hedef " + host,
                        "Gorunen link ile tiklaninca gidilen adres farkli - klasik phishing."))

        ip = canonical_ip(host)
        if ip:
            # 3232235777 and 0xC0A80101 are the same address as 192.168.1.1 to a
            # browser. Show what it resolves to - the odd spelling is the point.
            disguised = ip != host
            add(Indicator("ip_url", "url", "high", 14,
                where + "Baglanti dogrudan IP adresi: " + host
                + (" (= " + ip + ")" if disguised else ""),
                "Mesru kurumlar linklerde ciplak IP kullanmaz."
                + (" Adres ondalik/hex/sekizlik yazilarak IP oldugu gizlenmis."
                   if disguised else "")))
        if "@" in _authority(link.href):
            add(Indicator("at_in_url", "url", "medium", 10,
                where + "URL yetki kisminda '@': " + link.href,
                "'@' oncesi kisim yok sayilir; gercek host gizlenir."))
        if rdom in SHORTENERS:
            add(Indicator("url_shortener", "url", "medium", 8,
                where + "URL kisaltici: " + rdom,
                "Kisaltici gercek hedefi gizler."))
        if host.count(".") >= 4:
            add(Indicator("excessive_subdomains", "url", "low", 6,
                where + "Asiri subdomain: " + host,
                "Marka adini subdomain'e gomerek mesru gosterme taktigi."))

        if not ip:
            domain_checks(host, rdom, where)

    # The sender's own domain is asked the same questions. A typosquat used only
    # as the From address (noreply@paypa1.com, no link to it) never met a URL
    # check. After the links and through the same add(): one domain, one finding.
    for label, addr in (("Gonderen (From) domaini - ", getattr(email, "from_addr", "")),
                        ("Reply-To domaini - ", getattr(email, "reply_to", ""))):
        host = domain_of_address(addr or "")
        if host and not canonical_ip(host):
            domain_checks(host, registered_domain(host), where=label)
    return out
