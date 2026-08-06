"""Body/content checks: urgency language, credential requests, brand impersonation."""
from __future__ import annotations
import re

from ..indicators import Indicator
from ..util import registered_domain

# Credential / sensitive-data solicitation (TR + EN).
CRED_PAT = re.compile(
    r"(password|şifre|parola|otp|one[\s-]?time|pin\s*kod|tc\s*kimlik|"
    r"social security|ssn|cvv|kart\s*numaras|card\s*number)",
    re.IGNORECASE,
)

GENERIC_GREETING = re.compile(
    r"(dear\s+(customer|user|member)|sayın\s+(müşteri|kullanıcı|üye))",
    re.IGNORECASE,
)


def run(email, online=False, ctx=None):
    ctx = ctx or {}
    urgency = ctx.get("urgency", [])
    brands = ctx.get("brands", {})
    out = []

    blob = (email.subject or "") + "\n" + (email.text_body or "") + "\n" + (email.html_body or "")
    low = blob.lower()

    hits = [k for k in urgency if k in low]
    if hits:
        w = min(4 + 2 * len(hits), 12)
        sev = "medium" if len(hits) >= 2 else "low"
        out.append(Indicator("urgency_language", "content", sev, w,
            "Aciliyet ifadeleri: " + ", ".join(sorted(set(hits))[:5]),
            "Aciliyet/tehdit dili kurbanı düşünmeden hareket etmeye iter."))

    if CRED_PAT.search(blob):
        out.append(Indicator("credential_request", "content", "high", 12,
            "Kimlik bilgisi isteyen ifade tespit edildi",
            "Meşru kurumlar e-postayla şifre/OTP/kart bilgisi istemez."))

    if GENERIC_GREETING.search(blob):
        out.append(Indicator("generic_greeting", "content", "low", 4,
            "Genel hitap ('Sayın müşteri' vb.)",
            "Toplu phishing kişiye özel hitap kullanamaz."))

    # Brand impersonation - IDENTITY-based, not a mere mention.
    #
    # Merely referencing a brand in the body ("pay with PayPal") is normal in
    # legitimate mail and caused constant false alarms. Real impersonation is the
    # sender *claiming to be* the brand: the brand name in the From display name
    # or From address while the From domain is NOT one of the brand's real
    # domains. A word boundary avoids substring hits (grapple != apple), and an
    # authenticated brand-owned domain (e.g. paypalmarketing.com) is exempted.
    fdom = registered_domain(email.from_domain)
    auth_ok = ctx.get("auth_level") == "pass"
    identity = ((email.from_display or "") + " " + (email.from_addr or "")).lower()
    for brand, domains in brands.items():
        if fdom in domains:
            continue  # the sender genuinely IS the brand
        if not re.search(r"(^|[^a-z0-9])" + re.escape(brand) + r"([^a-z0-9]|$)", identity):
            continue  # brand not claimed in the sender identity
        if auth_ok and brand in fdom:
            continue  # authenticated brand-owned domain (paypal -> paypalmarketing.com)
        out.append(Indicator("brand_impersonation", "content", "high", 16,
            "Gönderen kimliğinde '" + brand + "' geçiyor ama domain " + (fdom or email.from_domain or "?"),
            "Gönderen adı/adresi " + brand + " kimliğine bürünüyor fakat resmi domaininden gelmiyor."))
        break
    return out
