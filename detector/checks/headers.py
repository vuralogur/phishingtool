"""Header / authentication checks: SPF/DKIM/DMARC, address mismatches, spoofing."""
from __future__ import annotations
import re

from ..indicators import Indicator
from ..util import registered_domain, domain_of_address, looks_like_domain

# Whole dotted name, not the first two labels: "www.paypal.com" must not be read
# as "www.paypal", which has no public suffix and would be discarded below.
_DOMAIN_TOKEN = re.compile(r"(?:[\w-]+\.)+[a-z]{2,}")

_MECHS = ("spf", "dkim", "dmarc")
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

    if email.reply_to:
        rdom = registered_domain(domain_of_address(email.reply_to))
        if fdom and rdom and rdom != fdom:
            out.append(Indicator("from_replyto_mismatch", "auth", "medium", 10,
                "From=" + email.from_addr + "  Reply-To=" + email.reply_to,
                "Yanit farkli bir domaine gidiyor - cevaplari saldirgana yonlendirme taktigi."))

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
