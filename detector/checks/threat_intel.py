"""What third parties already know about where a mail points.

* **Threat lists - OFFLINE.** Links and the sender's domain are looked up in
  the lists the user downloaded with ``phishingtool feeds update``
  (``detector/feeds.py``). The lookup is a dictionary read; nothing leaves the
  machine. No downloaded list = no finding, and the run is exactly what it was
  before this module existed.
* **Domain age - ONLINE** (``--online`` only). RDAP is asked when the sender's
  and the linked domains were registered (``detector/rdap.py``); the request
  carries the registrable domain and nothing else.

A list is somebody else's judgement and lists contain mistakes and shared
hosts, so three things are never matched by host alone: a brand's or an
allowlisted domain, a URL shortener, and the front door of a free-hosting
service. One exact listed address on such a host is still a hit.
"""
from __future__ import annotations
from urllib.parse import urlparse

from .. import rdap
from ..feeds import LABELS
from ..indicators import Indicator
from ..util import canonical_ip, domain_of_address, link_origin, registered_domain
from .headers import FREEMAIL
from .urls import SHORTENERS

NEW_DOMAIN_DAYS = 30     # registered more recently than this = "new"
MAX_AGE_LOOKUPS = 5      # RDAP questions per mail


def _host(href) -> str:
    try:
        return (urlparse(href).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _protected(ctx) -> set:
    """Domains a block list is not allowed to condemn wholesale."""
    out = set(ctx.get("allowlist") or ()) | set(ctx.get("own_domains") or ())
    for domains in (ctx.get("brands") or {}).values():
        out |= set(domains)
    return out


def _excused(hit, host, ctx, protected) -> bool:
    """A host-level match on a host that many unrelated parties share."""
    if hit.kind == "url":
        return False      # that exact address is listed - whoever hosts it
    rdom = registered_domain(host)
    if host in protected or rdom in protected:
        return True
    # x.pages.dev listed as a host is one tenant and counts; "pages.dev" itself
    # (or bit.ly) is everybody.
    apex = rdom if hit.kind == "domain" else host
    return apex in SHORTENERS or apex in (ctx.get("free_hosting") or ())


def _listed(feeds, hit) -> str:
    """"OpenPhish listesinde (liste tarihi 2026-11-15)" - with a staleness note."""
    text = LABELS.get(hit.source, hit.source) + " listesinde"
    info = feeds.info(hit.source)
    if info is not None and info.fetched is not None:
        text += " (liste tarihi " + info.fetched.strftime("%Y-%m-%d")
        if info.stale():
            text += ", " + str(info.age_days()) + " gun eski - `phishingtool feeds update`"
        text += ")"
    return text


def _feed_hits(email, ctx) -> list:
    feeds = ctx.get("feeds")
    if not feeds:
        return []
    protected = _protected(ctx)
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
        hit = feeds.lookup(link.href)
        if hit is None or _excused(hit, host, ctx, protected):
            continue
        where = link_origin(link)
        if hit.kind == "path":
            add(Indicator("threat_feed_neighbor", "reputation", "medium", 10,
                where + host + " - bu host'taki baska bir adres "
                + _listed(feeds, hit),
                "Linkin kendisi listede degil, ayni host'taki baska bir sayfa "
                "listede. Host tumuyle saldirgana ait olabilir; paylasimli bir "
                "servis de olabilir - tek basina kanit degildir."))
        else:
            what = {"url": "tam adres ", "host": "",
                    "domain": "domain " + hit.entry + " "}[hit.kind]
            add(Indicator("threat_feed_hit", "reputation", "critical", 25,
                where + host + " - " + what + _listed(feeds, hit),
                "Baglanti, indirilmis bir tehdit listesinde kayitli. Eslestirme "
                "yerelde yapildi; hicbir yere sorgu gonderilmedi."))

    for label, domain in (("Gonderen", email.from_domain),
                          ("Reply-To", domain_of_address(email.reply_to or ""))):
        domain = (domain or "").lower().rstrip(".")
        if not domain or domain in FREEMAIL:
            continue
        hit = feeds.lookup_host(domain)
        if hit is None or _excused(hit, domain, ctx, protected):
            continue
        add(Indicator("threat_feed_hit", "reputation", "critical", 25,
            label + " domaini " + domain + " - " + _listed(feeds, hit),
            "Gonderenin domaini, indirilmis bir tehdit listesinde kayitli. "
            "Eslestirme yerelde yapildi; hicbir yere sorgu gonderilmedi."))
    return out


def _age_candidates(email, ctx) -> list:
    """(registrable domain, evidence prefix) worth asking about, sender first."""
    protected = _protected(ctx)
    free = ctx.get("free_hosting") or ()
    out = []

    def consider(host, where):
        host = (host or "").lower().rstrip(".")
        if not host or canonical_ip(host):
            return
        rdom = registered_domain(host)
        # Old and shared by definition: asking about gmail.com, bit.ly or
        # pages.dev says nothing about this mail.
        if (not rdom or "." not in rdom or rdom in protected or rdom in FREEMAIL
                or rdom in SHORTENERS or rdom in free
                or any(host == s or host.endswith("." + s) for s in free)):
            return
        if all(rdom != seen for seen, _ in out):
            out.append((rdom, where))

    consider(email.from_domain, "Gonderen domaini ")
    consider(domain_of_address(email.reply_to or ""), "Reply-To domaini ")
    for link in email.links:
        consider(_host(link.href), link_origin(link) + "Link domaini ")
    return out[:MAX_AGE_LOOKUPS]


def _domain_age(email, ctx) -> list:
    authed = ctx.get("auth_level") == "pass"
    for rdom, where in _age_candidates(email, ctx):
        age = rdap.age_days(rdom)
        if age is None or not 0 <= age < NEW_DOMAIN_DAYS:
            continue
        if authed:
            # A new domain can pass DMARC on its first day - so can a new
            # company's. Hard, but not enough to carry a verdict alone.
            return [Indicator("newly_registered_domain", "url", "medium", 6,
                where + rdom + " " + str(age) + " gun once kaydedilmis (RDAP), "
                "gonderen dogrulanmis: DMARC pass",
                "Domain cok yeni. Phishing domainleri kullanilmadan gunler once "
                "kaydedilir; yeni kurulmus mesru bir isletme de olabilir.")]
        return [Indicator("newly_registered_domain", "url", "high", 12,
            where + rdom + " " + str(age) + " gun once kaydedilmis (RDAP)",
            "Domain cok yeni. Phishing domainleri kullanilmadan gunler once "
            "kaydedilir ve birkac gun icinde kapatilir.")]
    return []


def run(email, online=False, ctx=None):
    ctx = ctx or {}
    out = _feed_hits(email, ctx)
    if online:
        out += _domain_age(email, ctx)
    return out
