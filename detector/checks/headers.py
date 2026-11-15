"""Header / authentication checks: SPF/DKIM/DMARC, address mismatches, spoofing."""
from __future__ import annotations
import re
from email.utils import parseaddr

from ..indicators import Indicator
from ..util import registered_domain, domain_of_address, looks_like_domain

# Whole dotted name, not the first two labels: "www.paypal.com" must not be read
# as "www.paypal", which has no public suffix and would be discarded below.
_DOMAIN_TOKEN = re.compile(r"(?:[\w-]+\.)+[a-z]{2,}")

_MECHS = ("spf", "dkim", "dmarc")

# Mailbox providers anyone can sign up to. A Reply-To pointing at one of these
# from a corporate From is the BEC shape; a Reply-To pointing at a help-desk or
# CRM domain is how half the internet's support mail works.
FREEMAIL = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "windowslive.com", "yahoo.com", "ymail.com", "aol.com",
    "icloud.com", "me.com", "proton.me", "protonmail.com", "tutanota.com",
    "tuta.io", "gmx.com", "gmx.net", "mail.com", "mail.ru", "yandex.com",
    "yandex.ru", "yandex.com.tr", "hotmail.com.tr", "outlook.com.tr",
    "yahoo.com.tr", "mynet.com",
})
_SPF_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror",
                "permerror"}
# How much trust a result buys. Used only to notice that a LOWER header claims
# more than the authoritative one - never to compute the score.
_TRUST_RANK = {"pass": 2, "softfail": 1, "fail": 1}


def _stated(line) -> dict:
    """One Authentication-Results header -> the {mechanism: result} it states."""
    out = {}
    for mech in _MECHS:
        m = re.search(r"\b" + mech + r"\s*=\s*(\w+)", str(line or ""), re.IGNORECASE)
        if m:
            out[mech] = m.group(1).lower()
    return out


def _ar_stack(email) -> list:
    """Authentication-Results headers, newest first, empty ones dropped."""
    return [s for s in (_stated(l) for l in getattr(email, "auth_results", []) or [])
            if s]


def _received_spf(email) -> str:
    """Received-SPF states its result as the first token, not as 'spf=...'."""
    for line in getattr(email, "spf_received", []) or []:
        m = re.match(r"\s*([A-Za-z]+)", str(line or ""))
        if m and m.group(1).lower() in _SPF_RESULTS:
            return m.group(1).lower()
    return ""


_AR_COMMENT = re.compile(r"\([^()]*\)")
_AR_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)
_AR_PROP = re.compile(
    r"\b(header\.d|header\.i|header\.from|smtp\.mailfrom|smtp\.helo)\s*=\s*([^\s;]+)",
    re.IGNORECASE)
# Which property names the domain a mechanism actually vouched for.
_AR_SUBJECT = {"dmarc": ("header.from",), "dkim": ("header.d", "header.i"),
               "spf": ("smtp.mailfrom", "smtp.helo")}


def _top_auth_results(email) -> str:
    """The Authentication-Results line summary() reads, as written."""
    for line in getattr(email, "auth_results", []) or []:
        if _stated(line):
            return str(line)
    return ""


def alignment(email):
    """Whose domain did the passing results vouch for? -> (state, foreign).

    "spf=pass" says the *envelope* domain authorised the sending server, and
    "dkim=pass" that *some* domain signed the mail. Neither says anything about
    the From address unless that domain is the From domain - anyone can pass SPF
    and DKIM for a domain they registered this morning, with any From they like.

    state is one of
      "aligned"   - a pass names the From domain (or DMARC passed, which is this
                    very test done by the receiver)
      "unaligned" - every pass names some other domain; ``foreign`` lists them
      "unknown"   - a pass that does not say which domain it was for
      "nopass"    - the receiver stated results and none of them is a pass
      "none"      - no Authentication-Results to read
    Compared at registrable-domain level, as DMARC's relaxed alignment does.
    """
    line = _top_auth_results(email)
    if not line:
        return "none", []
    while True:  # comments nest, and they may contain ";" and "="
        stripped = _AR_COMMENT.sub(" ", line)
        if stripped == line:
            break
        line = stripped
    fdom = registered_domain(email.from_domain)
    aligned = unknown = False
    foreign = []
    for clause in line.split(";"):
        m = _AR_RESULT.search(clause)
        if not m or m.group(2).lower() != "pass":
            continue
        mech = m.group(1).lower()
        props = {k.lower(): v for k, v in _AR_PROP.findall(clause)}
        claimed = next((props[k] for k in _AR_SUBJECT[mech] if k in props), "")
        if not claimed:
            # DMARC is defined on the From domain; a bare SPF/DKIM pass is not.
            if mech == "dmarc":
                aligned = True
            else:
                unknown = True
            continue
        dom = registered_domain(claimed.strip("\"'<>").rsplit("@", 1)[-1])
        if dom and fdom and dom == fdom:
            aligned = True
        else:
            # Includes "dmarc=pass header.from=other.com": the receiver judged a
            # From this mail does not show - the two-From-headers trick.
            foreign.append(mech + "=pass (" + (dom or "?") + ")")
    if aligned:
        return "aligned", foreign
    if unknown:
        return "unknown", foreign
    if foreign:
        return "unaligned", foreign
    return "nopass", []


def _brand_of(domain: str, brands: dict) -> str:
    """The brand whose genuine domain this is, "" if it is nobody's."""
    for brand, domains in (brands or {}).items():
        if domain in domains:
            return brand
    return ""


def summary(email):
    """SPF/DKIM/DMARC as judged by the LAST server that handled this mail.

    Only the topmost Authentication-Results counts. Headers are prepended, so
    everything below the top one was already in the message before it reached
    the boundary you trust - including anything the sender wrote themselves. A
    mail that carries its own "dmarc=pass" line must not be read as authenticated
    just because no genuine verdict mentions DMARC, so a mechanism the top header
    is silent about stays "none" instead of being filled in from further down.
    """
    stack = _ar_stack(email)
    top = stack[0] if stack else {}
    out = {mech: top.get(mech, "none") for mech in _MECHS}
    if "spf" not in top:
        # The topmost Received-SPF was written by the same boundary MTA, so it
        # carries the same trust as the A-R header we just preferred.
        out["spf"] = _received_spf(email) or "none"
    return out


def unverifiable_auth(email) -> bool:
    """True when the mail claims a passing result that nothing corroborates.

    A genuine Authentication-Results is written by the server that also stamps a
    Received line. A message claiming "dmarc=pass" while carrying no Received
    header at all was never handled by that server, so the claim is the sender's
    own - and believing it would discount every soft signal to 30%. An Outlook
    .msg that simply lost its internet headers is excluded: there the gap belongs
    to the file format, not to the sender.
    """
    if getattr(email, "header_source", "rfc822") == "mapi":
        return False
    if getattr(email, "received", None):
        return False
    return "pass" in summary(email).values()


def _conflict(stack) -> str:
    """Mechanisms a lower Authentication-Results rates better than the top one.

    Benign after a forward (each hop judges what it saw) and identical to what a
    hand-written header looks like, so this is reported and never scored.
    """
    if len(stack) < 2:
        return ""
    top, notes = stack[0], []
    for mech in _MECHS:
        best = max((s.get(mech, "none") for s in stack[1:]),
                   key=lambda r: _TRUST_RANK.get(r, 0))
        if _TRUST_RANK.get(best, 0) > _TRUST_RANK.get(top.get(mech, "none"), 0):
            notes.append(mech + "=" + best + " (ust satir: " +
                         top.get(mech, "belirtmemis") + ")")
    return ", ".join(notes)


def run(email, online=False, ctx=None):
    out = []
    a = summary(email)

    # RFC 5322 allows exactly one From. With two, the gateway that checked SPF/
    # DMARC and the client that shows the sender may each pick a different one -
    # and every check here, like the parser, has read only the first.
    froms = (getattr(email, "headers", {}) or {}).get("from", [])
    addresses = sorted({parseaddr(v)[1].lower() for v in froms} - {""})
    if len(froms) > 1 and len(addresses) > 1:
        out.append(Indicator("multiple_from_headers", "auth", "high", 14,
            "Birden fazla From basligi: " + ", ".join(addresses[:4]),
            "Mailde iki farkli gonderen yaziyor. Dogrulamayi yapan sunucu birini, "
            "postayi gosteren istemci digerini okuyabilir; analiz ilkine gore yapildi."))

    if getattr(email, "header_source", "rfc822") == "mapi":
        # Outlook saved this .msg without PR_TRANSPORT_MESSAGE_HEADERS. Say so
        # instead of letting "spf=none, dkim=none, no Received" read like a
        # finding: the records are missing from the FILE, not from the mail.
        out.append(Indicator("msg_no_transport_headers", "auth", "low", 0,
            ".msg icinde internet basliklari (PR_TRANSPORT_MESSAGE_HEADERS) yok",
            "Basliklar Outlook'un MAPI alanlarindan kuruldu: gonderen, konu, govde, "
            "linkler ve ekler normal analiz edildi; SPF/DKIM/DMARC ve Received "
            "zinciri bu dosyada hic bulunmadigi icin dogrulanamiyor - basarisiz "
            "sayilmadi. Kaynak sunucu analizi icin maili .eml olarak disari aktarin."))

    if a["spf"] in ("fail", "softfail"):
        sev, w = ("high", 15) if a["spf"] == "fail" else ("medium", 8)
        out.append(Indicator("spf_" + a["spf"], "auth", sev, w,
            "Authentication-Results: spf=" + a["spf"],
            "Gonderen sunucu From domaininin SPF politikasinda yetkili degil - sahtecilik isareti."))
    if a["dkim"] == "fail":
        out.append(Indicator("dkim_fail", "auth", "high", 12,
            "Authentication-Results: dkim=fail",
            "DKIM imzasi dogrulanamadi - icerik degistirilmis veya taklit."))
    if a["dmarc"] == "fail":
        out.append(Indicator("dmarc_fail", "auth", "high", 15,
            "Authentication-Results: dmarc=fail",
            "DMARC basarisiz - domain sahibinin politikasina gore bu mail reddedilmeli."))

    if unverifiable_auth(email):
        out.append(Indicator("auth_claim_unverifiable", "auth", "medium", 8,
            "Basarili auth sonucu var ama hic Received basligi yok: " +
            "spf=" + a["spf"] + " dkim=" + a["dkim"] + " dmarc=" + a["dmarc"],
            "Authentication-Results'i mailin gectigi sunucu yazar ve ayni sunucu "
            "Received satiri da ekler. Received hic yokken 'pass' iddiasi "
            "gonderenin kendi yazdigi satirdir - skorlamada dogrulanmis "
            "sayilmadi."))

    clash = _conflict(_ar_stack(email))
    if clash:
        out.append(Indicator("auth_results_conflict", "auth", "low", 5,
            "Alt Authentication-Results satiri daha iyi sonuc iddia ediyor: " + clash,
            "Skorlamada yalnizca en ustteki (son sunucunun yazdigi) sonuc kullanildi. "
            "Alttaki satirlar mail buraya varmadan once eklenmistir - yonlendirilmis "
            "mailde normaldir, ancak gonderenin kendi yazdigi sahte satir da boyle gorunur."))

    fdom = registered_domain(email.from_domain)
    from_mapi = getattr(email, "header_source", "rfc822") == "mapi"

    state, foreign = alignment(email)
    if state == "unaligned":
        out.append(Indicator("auth_pass_unaligned", "auth", "low", 4,
            "Basarili sonuclar From domaini (" + (fdom or "?") + ") icin degil: "
            + ", ".join(foreign),
            "SPF/DKIM baska bir domain adina gecmis. Bu, o domainin sahibinin "
            "gonderdigini kanitlar - From adresinin gercek oldugunu degil. "
            "Skorlamada dogrulanmis gonderen sayilmadi."))

    # A From address ON a known brand's real domain. content.py skips these
    # ("the sender genuinely is the brand") - which is only true if something
    # proves it. Brands this size all publish DMARC, so the receiving server's
    # verdict settles it; without one, say so instead of assuming either way.
    brand = "" if fdom in FREEMAIL else _brand_of(fdom, (ctx or {}).get("brands"))
    if brand and not from_mapi:
        stated = "spf=" + a["spf"] + " dkim=" + a["dkim"] + " dmarc=" + a["dmarc"]
        self_claimed = unverifiable_auth(email)
        if state in ("unaligned", "nopass") or (state != "none" and self_claimed):
            out.append(Indicator("brand_domain_spoof", "auth", "high", 18,
                "From " + email.from_addr + " (" + brand + " domaini) ama hizali "
                "dogrulama yok: " + stated
                + (" - 'pass' satirini damgalayan sunucu yok" if self_claimed else ""),
                "Mail " + brand + " markasinin gercek domaininden geldigini soyluyor, "
                "fakat alici sunucu o domain adina gecen bir SPF/DKIM/DMARC sonucu "
                "yazmamis. Gercek " + brand + " maili bu kontrolden gecer; From "
                "satirini herkes istedigi gibi yazabilir."))
        elif state == "none":
            out.append(Indicator("brand_domain_unverified", "auth", "low", 8,
                "From " + email.from_addr + " (" + brand + " domaini) - bu dosyada "
                "Authentication-Results yok",
                "Gonderen adresi " + brand + " domaininde ama mailde alici sunucunun "
                "dogrulama sonucu bulunmuyor: gercek de olabilir, taklit de. "
                "Kesinlestirmek icin --online ile canli SPF/DKIM dogrulamasi yapin."))

    if email.reply_to:
        rdom = registered_domain(domain_of_address(email.reply_to))
        if fdom and rdom and rdom != fdom:
            # A sender proven to own its From domain (DMARC pass) that points
            # replies at another *organisation's* domain is a ticketing system or
            # a CRM. Still reported - at a weight that cannot carry a verdict by
            # itself. Unauthenticated, or replies going to a free mailbox, stays
            # at full weight: that is what redirecting the answer looks like.
            authed = (ctx or {}).get("auth_level") == "pass"
            routine = authed and rdom not in FREEMAIL
            out.append(Indicator("from_replyto_mismatch", "auth",
                "low" if routine else "medium", 5 if routine else 10,
                "From=" + email.from_addr + "  Reply-To=" + email.reply_to,
                "Yanit farkli bir domaine gidiyor - cevaplari saldirgana yonlendirme taktigi."
                + (" Gonderen dogrulanmis (DMARC pass) ve hedef ucretsiz posta "
                   "kutusu degil; destek/CRM sistemlerinde olagan - dusuk agirlik."
                   if routine else "")))

    if email.return_path:
        pdom = registered_domain(domain_of_address(email.return_path))
        if fdom and pdom and pdom != fdom:
            out.append(Indicator("from_returnpath_mismatch", "auth", "medium", 8,
                "From=" + email.from_addr + "  Return-Path=" + email.return_path,
                "Zarf gonderici (Return-Path) From ile uyusmuyor - spoofing gostergesi."))

    # Display-name spoof: display name references a domain different from the real one.
    # looks_like_domain: "Kargo Ltd.Sti" matches the domain regex but is not a
    # domain, and reading it as one flagged ordinary corporate mail as spoofed.
    m = _DOMAIN_TOKEN.search((email.from_display or "").lower())
    if m and fdom and looks_like_domain(m.group(0)):
        ddom = registered_domain(m.group(0))
        if ddom and ddom != fdom:
            out.append(Indicator("display_name_spoof", "auth", "high", 18,
                "Gorunen ad '" + email.from_display + "' -> gercek adres " + email.from_addr,
                "Gorunen ad baska bir kurumu ima ediyor ama gercek gonderen adresi farkli."))

    if online:
        out += _online(email)
    return out


def _online(email):
    out = []
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return out
    dom = registered_domain(email.from_domain)
    if not dom:
        return out
    try:
        answers = dns.resolver.resolve(dom, "TXT")
        txt = " ".join(str(r) for r in answers).lower()
        if "v=spf1" not in txt:
            out.append(Indicator("no_spf_record", "auth", "medium", 8,
                dom + " TXT kaydinda v=spf1 yok",
                "Domainin SPF kaydi yok - spoofing'e karsi korumasiz."))
    except Exception:
        pass
    return out
