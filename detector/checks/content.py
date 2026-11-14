"""Body/content checks: urgency language, credential requests, brand impersonation."""
from __future__ import annotations
import re

from ..indicators import Indicator
from ..util import ascii_fold, registered_domain, skeleton

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
    # "Musteri numaraniz: 123" and "IBAN: TR.." sit on every bill - that is the
    # sender GIVING a number. Only the asking form counts: "...numaranizi girin",
    # "IBAN bilgilerinizi gonderin".
    r"musteri\s*numaranizi|iban\s*(?:numaranizi|bilgilerinizi|bilginizi)|"
    r"iban\W?inizi|kredi\s*karti\s*bilgi|2fa\b|mfa\s*code|"
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
        # The words alone cannot tell a phish from the real "reset your password"
        # or "your one-time code is ..." mail - they are the same words. What
        # differs is who sent it. From a sender proven to own its From domain
        # (DMARC pass) the topic is reported at a weight that cannot carry a
        # verdict by itself; it still adds to any other hard evidence. Anyone
        # unauthenticated talking about passwords keeps the full weight.
        if ctx.get("auth_level") == "pass":
            out.append(Indicator("credential_request", "content", "medium", 6,
                "Kimlik bilgisi konulu ifade (gönderen doğrulanmış: DMARC pass)",
                "Şifre/OTP/kart bilgisi geçiyor. Gönderen From domaininin sahibi "
                "olduğunu kanıtladığı için düşük ağırlık — şifre sıfırlama ve "
                "tek kullanımlık kod mailleri de aynı kelimeleri kullanır."))
        else:
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
    # The same identity as the eye reads it: look-alike letters mapped to Latin,
    # zero-width characters dropped. "PаyPal" (Cyrillic а) and "Pay<ZWSP>Pal"
    # are written that way precisely so that the comparison above misses them.
    disguised_identity = (skeleton(email.from_display or "") + " "
                          + ascii_fold(email.from_addr or ""))
    for brand, domains in brands.items():
        if fdom in domains:
            continue  # the brand's own domain; headers.py checks it is not spoofed
        token = ascii_fold(brand)
        pattern = r"(^|[^a-z0-9])" + re.escape(token) + r"([^a-z0-9]|$)"
        plain = bool(re.search(pattern, identity))
        if not plain and not re.search(pattern, disguised_identity):
            continue  # brand not claimed in the sender identity
        if auth_ok and token in ascii_fold(fdom):
            continue  # authenticated brand-owned domain (paypal -> paypalmarketing.com)
        out.append(Indicator("brand_impersonation", "content", "high", 16,
            "Gönderen kimliğinde '" + brand + "' geçiyor ama domain " + (fdom or email.from_domain or "?")
            + ("" if plain else " — ad benzer/görünmez karakterlerle yazılmış: "
               + ascii(email.from_display or "")),
            "Gönderen adı/adresi " + brand + " kimliğine bürünüyor fakat resmi domaininden gelmiyor."
            + ("" if plain else " Marka adı Latin dışı benzer harfler veya sıfır-genişlik "
               "karakterlerle gizlenmiş — metin filtrelerinden kaçmak için yapılır.")))
        break
    return out
