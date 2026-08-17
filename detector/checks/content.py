"""Body/content checks: urgency language, credential requests, brand impersonation."""
from __future__ import annotations
import re

from ..indicators import Indicator
from ..util import ascii_fold, registered_domain

# All three patterns below run against ascii_fold(text), never the raw body, so
# they are written in the folded alphabet: "sifre" matches ŞİFRE, Şifre and
# sifre alike. str.lower() alone cannot do this - it turns "I" into "i" and
# never into "ı", so a Turkish keyword can miss the ALL-CAPS subject lines
# phishing is full of.

# Credential / sensitive-data solicitation (TR + EN).
CRED_PAT = re.compile(
    r"(password|sifre|parola|otp\b|one[\s-]?time|pin\s*kod|tc\s*kimlik|"
    r"kimlik\s*numara|social security|ssn\b|cvv|cvc\b|kart\s*numaras|"
    r"card\s*number|son\s*kullanma\s*tarih|guvenlik\s*kodu|dogrulama\s*kodu|"
    r"sms\s*kodu|tek\s*kullanimlik\s*sifre|internet\s*sube\s*sifre|"
    r"musteri\s*numara|iban\b|kredi\s*karti\s*bilgi|2fa\b|mfa\s*code|"
    r"authenticator|seed\s*phrase|recovery\s*phrase|private\s*key|"
    r"cuzdan\s*anahtar)",
    re.IGNORECASE,
)

GENERIC_GREETING = re.compile(
    r"(dear\s+(customer|user|member|valued|sir\s*/?\s*madam)|"
    r"sayin\s+(musteri|kullanici|uye|yetkili|ilgili)|"
    r"degerli\s+(musteri|kullanici|uyemiz)|"
    r"merhaba\s+(kullanici|musteri)\b)",
    re.IGNORECASE,
)


def run(email, online=False, ctx=None):
    ctx = ctx or {}
    urgency = ctx.get("urgency", [])
    brands = ctx.get("brands", {})
    out = []

    blob = (email.subject or "") + "\n" + (email.text_body or "") + "\n" + (email.html_body or "")
    low = ascii_fold(blob)

    # Both sides folded: a dictionary written with "ı/ş/ğ" still matches a body
    # written without them, and vice versa. Evidence quotes the dictionary entry
    # as the user wrote it, not the folded form.
    hits = [k for k in urgency if ascii_fold(k) in low]
    if hits:
        w = min(4 + 2 * len(hits), 12)
        sev = "medium" if len(hits) >= 2 else "low"
        out.append(Indicator("urgency_language", "content", sev, w,
            "Aciliyet ifadeleri: " + ", ".join(sorted(set(hits))[:5]),
            "Aciliyet/tehdit dili kurbanı düşünmeden hareket etmeye iter."))

    if CRED_PAT.search(low):
        out.append(Indicator("credential_request", "content", "high", 12,
            "Kimlik bilgisi isteyen ifade tespit edildi",
            "Meşru kurumlar e-postayla şifre/OTP/kart bilgisi istemez."))

    if GENERIC_GREETING.search(low):
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
    identity = ascii_fold((email.from_display or "") + " " + (email.from_addr or ""))
    for brand, domains in brands.items():
        if fdom in domains:
            continue  # the sender genuinely IS the brand
        token = ascii_fold(brand)
        if not re.search(r"(^|[^a-z0-9])" + re.escape(token) + r"([^a-z0-9]|$)", identity):
            continue  # brand not claimed in the sender identity
        if auth_ok and token in ascii_fold(fdom):
            continue  # authenticated brand-owned domain (paypal -> paypalmarketing.com)
        out.append(Indicator("brand_impersonation", "content", "high", 16,
            "Gönderen kimliğinde '" + brand + "' geçiyor ama domain " + (fdom or email.from_domain or "?"),
            "Gönderen adı/adresi " + brand + " kimliğine bürünüyor fakat resmi domaininden gelmiyor."))
        break
    return out
