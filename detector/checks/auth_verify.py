"""Tier 1 — cryptographic authentication verification.

Instead of only *reading* the Authentication-Results header (which an attacker
can forge), this module VERIFIES:

  * Received-chain / originating-IP forensics  -> OFFLINE
  * DKIM signature (real crypto verify)        -> ONLINE (needs DNS pubkey)
  * SPF live evaluation against sending IP      -> ONLINE (needs DNS)
  * DMARC policy + presence                     -> ONLINE (needs DNS)

Online checks run only when online=True and degrade silently on any error.
"""
from __future__ import annotations
import ipaddress
import re

from ..indicators import Indicator
from ..util import registered_domain, domain_of_address
from . import headers as _headers

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def run(email, online=False, ctx=None):
    out = _received_forensics(email)
    if online:
        out += _dkim_verify(email)
        out += _spf_eval(email)
        out += _dmarc_policy(email)
    return out


# ---------- offline ----------
def _origin_ip(email):
    # Received headers are listed newest-first; the origin is the last one.
    for line in reversed(email.received):
        for m in _IP_RE.findall(line):
            try:
                return ipaddress.ip_address(m)
            except ValueError:
                continue
    return None


def _received_forensics(email):
    out = []
    if not email.received:
        if getattr(email, "header_source", "rfc822") == "mapi":
            # A .msg without saved internet headers never had a Received chain
            # to lose - that is Outlook's doing, not the sender's. headers.py
            # reports the gap; calling it possible injection here would be wrong.
            return out
        out.append(Indicator("no_received_headers", "auth", "low", 5,
            "Received başlığı yok",
            "Received zinciri yok — doğrudan enjeksiyon / spoof edilmiş olabilir."))
        return out
    ip = _origin_ip(email)
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_reserved):
        out.append(Indicator("private_origin_ip", "auth", "medium", 8,
            "Köken IP özel/ayrılmış: " + str(ip),
            "İlk gönderen IP RFC1918/özel aralıkta — internet kaynaklı görünmüyor."))
    return out


# ---------- online ----------
def _dkim_verify(email):
    if "dkim-signature" not in email.headers:
        return []
    try:
        import dkim  # type: ignore
        ok = dkim.verify(email.raw_bytes)
    except Exception:
        return []
    if not ok:
        return [Indicator("dkim_verify_fail", "auth", "high", 15,
            "DKIM imzası kriptografik doğrulamadan GEÇMEDİ (canlı)",
            "Başlık ne derse desin, imza tutmuyor — içerik değiştirilmiş/taklit.")]
    return []


def _mailfrom(email):
    return email.return_path or email.from_addr or ""


def _spf_eval(email):
    ip = _origin_ip(email)
    if ip is None or ip.is_private or ip.is_loopback:
        return []
    mailfrom = _mailfrom(email)
    dom = domain_of_address(mailfrom)
    if not dom:
        return []
    try:
        import spf  # type: ignore
        result, _ = spf.check2(i=str(ip), s=mailfrom, h=dom)
    except Exception:
        return []
    if result == "fail":
        return [Indicator("spf_live_fail", "auth", "high", 15,
            "Canlı SPF=fail: " + str(ip) + " " + dom + " için yetkili değil",
            "Gönderen IP, domainin SPF kaydında reddediliyor — spoofing.")]
    if result == "softfail":
        return [Indicator("spf_live_softfail", "auth", "medium", 8,
            "Canlı SPF=softfail: " + str(ip) + " / " + dom,
            "Gönderen IP SPF'te şüpheli işaretli.")]
    return []


def _dmarc_txt(domain):
    import dns.resolver  # type: ignore
    answers = dns.resolver.resolve("_dmarc." + domain, "TXT")
    for r in answers:
        txt = "".join(
            p.decode("utf-8", "replace") if isinstance(p, bytes) else str(p)
            for p in getattr(r, "strings", [str(r)])
        )
        if "v=dmarc1" in txt.lower():
            return txt
    return None


def _dmarc_policy(email):
    dom = registered_domain(email.from_domain)
    if not dom:
        return []
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return []
    try:
        txt = _dmarc_txt(dom)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        txt = None  # domain resolves but publishes no DMARC record
    except Exception:
        return []  # temporary / network error - do not flag
    if not txt:
        return [Indicator("no_dmarc_record", "auth", "medium", 8,
            dom + " için DMARC kaydı yok",
            "Domain DMARC yayınlamıyor — spoofing'e karşı politika uygulanamaz.")]
    m = re.search(r"\bp\s*=\s*(\w+)", txt, re.IGNORECASE)
    policy = m.group(1).lower() if m else "none"
    reported = _headers.summary(email)
    if policy in ("reject", "quarantine") and (
        reported["dkim"] == "fail" or reported["spf"] in ("fail", "softfail")
    ):
        return [Indicator("dmarc_policy_violation", "auth", "high", 15,
            "DMARC p=" + policy + " ama auth başarısız (dkim/spf)",
            "Domain politikası bu maili reddet/karantina diyor — güçlü spoofing sinyali.")]
    return []
