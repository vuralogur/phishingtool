"""Header / authentication checks: SPF/DKIM/DMARC, address mismatches, spoofing."""
from __future__ import annotations
import re

from ..indicators import Indicator
from ..util import registered_domain, domain_of_address

_DOMAIN_TOKEN = re.compile(r"[\w-]+\.\w{2,}")


def _auth_result(auth_lines, mech):
    """Extract e.g. spf=pass / dkim=fail / dmarc=none from Authentication-Results."""
    pat = re.compile(r"\b" + mech + r"\s*=\s*(\w+)", re.IGNORECASE)
    for line in auth_lines:
        m = pat.search(line)
        if m:
            return m.group(1).lower()
    return None


def summary(email):
    return {
        "spf": _auth_result(email.auth_results, "spf") or "none",
        "dkim": _auth_result(email.auth_results, "dkim") or "none",
        "dmarc": _auth_result(email.auth_results, "dmarc") or "none",
    }


def run(email, online=False, ctx=None):
    out = []
    a = summary(email)

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
    m = _DOMAIN_TOKEN.search((email.from_display or "").lower())
    if m and fdom:
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
