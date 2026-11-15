"""Social-engineering mail that carries no payload at all.

Every other check looks for a thing: a link, a form, an attachment, a forged
header. The mails below have none of them - the "payload" is a phone number to
call or a colleague to obey - and so they used to walk through with nothing
raised:

* callback phishing - a fake invoice / renewal notice whose only instruction
  is "call this number to cancel";
* business e-mail compromise - "are you at your desk? I need a transfer done
  today, I'm in a meeting, don't call";
* a changed-bank-details notice - the invoice is real, the account is not;
* a mail wearing the name of one of your own executives (``vip_names.txt``)
  from outside your own domains (``own_domains.txt``);
* a "RE:" subject on a mail that replies to nothing.

Wording alone proves little - honest invoices mention phone numbers and honest
managers ask for payments - so each finding is a CONJUNCTION: the wording, plus
the shape of the request, plus who is (not) vouching for the sender. Patterns
run against ``ascii_fold`` of the text the reader sees (subject + plain body +
``util.visible_text`` of the HTML), so they are written in the folded alphabet.
"""
from __future__ import annotations
import re

from ..indicators import Indicator
from ..util import ascii_fold, domain_of_address, registered_domain, skeleton, visible_text
from .headers import FREEMAIL

# A phone number as people write it: "+90 (212) 555 44 33", "0850 555 44 33",
# "1-888-555-0199". The match is then filtered by digit count in _phones().
_PHONE = re.compile(r"(?<![\w/.:-])(\+?\d[\d ().\-]{7,18}\d)(?![\w-])")
_DATE = re.compile(r"\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2}")

_CALL = re.compile(
    r"\b(call|dial|phone|contact (?:us|our|support|the)|reach (?:us|our)|helpline"
    r"|help ?desk|toll[\s-]?free|customer (?:care|service|support)"
    r"|support (?:team|line|number)"
    r"|ara(?:yin|yiniz|yarak|yabilirsiniz|maniz|yip)|ulas(?:in|iniz|abilirsiniz)"
    r"|iletisime gec\w*|musteri hizmetleri|destek hatti|cagri merkezi"
    r"|numarali hat\w*|telefon\w*)\b")
_CHARGE = re.compile(
    r"\b(subscription|renew(?:al|ed|s)?|auto[\s-]?renew\w*|invoice|charged?|debited"
    r"|billed|order (?:confirmation|number|id)|purchase|payment|transaction"
    r"|abonelig\w*|yenilen\w*|yenileme\w*|fatura\w*|tahsil\w*|cekil\w*|odeme\w*"
    r"|siparis\w*|uyelig\w*)\b")
_DISPUTE = re.compile(
    r"\b(cancel\w*|refund\w*|dispute\w*|unauthori[sz]ed"
    r"|did not (?:make|authori[sz]e|place)|didn'?t (?:make|authori[sz]e|place)"
    r"|iptal\w*|iade\w*|itiraz\w*|siz degilseniz|bilginiz disinda|yapmadiysaniz"
    r"|tanimiyorsaniz)\b")
_AMOUNT = re.compile(
    r"[$€£₺]\s?\d[\d.,]*|\d[\d.,]*\s?(?:tl|try|usd|eur|gbp|dolar|euro|lira)\b"
    r"|\b(?:usd|eur|gbp|try)\s?\d[\d.,]*", re.IGNORECASE)

_MONEY = re.compile(
    r"\b(wire transfer|bank transfer|wire (?:the )?(?:payment|funds|money)"
    r"|(?:make|process|send|arrange) (?:a |an |the |this )?(?:urgent )?(?:payment|transfer)"
    r"|transfer (?:of )?(?:funds|money)|gift ?cards?|itunes cards?|google play cards?"
    r"|pay (?:an |the |this )?invoice|outstanding invoice"
    r"|havale\w*|eft\b|odeme(?:yi|si|sini)? (?:yap|gonder|cik|gerceklestir)\w*"
    r"|para (?:gonder|transfer)\w*|hediye kart\w*|fatura(?:yi|nin|sini)? ode\w*)")
_PRETEXT = re.compile(
    r"\b(are you (?:available|free|at (?:your|the) desk|in the office|around)"
    r"|quick (?:task|favor|favour|request)|in a meeting"
    r"|can(?:'?t|not) (?:talk|take (?:a |any )?calls?|be reached)"
    r"|keep (?:this|it) (?:confidential|between us|discreet|quiet)"
    r"|strictly confidential|don'?t (?:tell|mention (?:this|it)|share this)"
    r"|sent from my (?:iphone|ipad|mobile|phone)"
    r"|musait mi\w*|toplantiday\w*|toplantiya gir\w*|arayam\w*"
    r"|telefon(?:la|a)? (?:gorusem\w*|bakam\w*|cevap verem\w*)"
    r"|aramizda kal\w*|kimseye (?:soyleme|bahsetme)\w*|gizli (?:tut|kal)\w*"
    r"|cok gizli)")

_BANK_NOUN = (r"(?:bank(?:ing)?|account|payment|remittance|wire|banka|hesap|iban|odeme)")
_BANK_INFO = (r"(?:details|information|info|instructions|bilgi\w*|numara\w*|hesab\w*)")
# "Changed", not merely "new": "hesap bilgileriniz ile yeni siparis" is a
# sentence about an order.
_BANK_VERB = (r"(?:has changed|have changed|changed|updated|been updated|is changing"
              r"|degis\w*|guncellen\w*)")
_BANK_CHANGE = re.compile(
    r"\b" + _BANK_NOUN + r" " + _BANK_INFO + r"[^.!?\n]{0,60}?\b" + _BANK_VERB
    + r"|\b(?:new|updated|changed|yeni|guncel\w*|degisen) " + _BANK_NOUN
    + r"(?: \w+)? " + _BANK_INFO)

_REPLY_SUBJECT = re.compile(r"^\s*(?:re|ynt|yanit|cevap|aw|sv)\s*:", re.IGNORECASE)

_BEC_MAX_CHARS = 1500     # BEC notes are short; a long mail is something else


def _phones(text: str) -> list:
    """(position, number) for everything written like a phone number."""
    out = []
    for m in _PHONE.finditer(text):
        raw = m.group(1).strip()
        digits = re.sub(r"\D", "", raw)
        if not (10 <= len(digits) <= 13 or (len(digits) == 7 and digits.startswith("444"))):
            continue
        # A bare run of digits is an order or customer number, not a phone.
        if not (raw.startswith("+") or re.search(r"[ ().\-]", raw)):
            continue
        if _DATE.search(raw):
            continue
        out.append((m.start(1), raw))
    return out


def _named_brand(low: str, brands: dict, from_rdom: str) -> str:
    """A known brand the text names while the sender is not that brand."""
    for brand, domains in brands.items():
        if from_rdom in domains:
            continue
        token = ascii_fold(brand)
        if len(token) >= 4 and re.search(
                r"(^|[^a-z0-9])" + re.escape(token) + r"([^a-z0-9]|$)", low):
            return brand
    return ""


def run(email, online=False, ctx=None):
    ctx = ctx or {}
    out = []
    brands = ctx.get("brands", {})
    authed = ctx.get("auth_level") == "pass"
    from_rdom = registered_domain(email.from_domain)
    from_free = (email.from_domain or "").lower() in FREEMAIL
    reply_rdom = registered_domain(domain_of_address(email.reply_to or ""))
    reply_elsewhere = bool(reply_rdom) and bool(from_rdom) and reply_rdom != from_rdom

    seen = visible_text(email.html_body or "")
    text = (email.subject or "") + "\n" + (email.text_body or "") + "\n" + seen
    low = ascii_fold(text)
    # Length of what the reader gets: the HTML and plain parts usually repeat
    # each other, so count the longer of the two, not their sum.
    length = max(len(email.text_body or ""), len(seen))

    # --- callback phishing ("call this number to cancel the charge") ---
    amount = _AMOUNT.search(text)
    if amount and _CHARGE.search(low) and _DISPUTE.search(low):
        for pos, number in _phones(low):
            window = low[max(0, pos - 160):pos + len(number) + 80]
            if not _CALL.search(window):
                continue
            brand = "" if authed else _named_brand(low, brands, from_rdom)
            if from_free or brand:
                who = ("ucretsiz posta adresinden (" + email.from_domain + ")" if from_free
                       else "'" + brand + "' adina, " + (from_rdom or "?") + " domaininden")
                out.append(Indicator("callback_phishing", "content", "high", 14,
                    "Ucret/yenileme bildirimi + 'iptal icin arayin' " + number + " - " + who,
                    "Geri-arama dolandiriciligi: mailde link ya da ek yoktur, kurban "
                    "numarayi kendisi arar ve telefonda uzaktan erisim programi "
                    "kurdurulur ya da kart bilgisi alinir."))
            break

    # --- changed bank details ---
    if _BANK_CHANGE.search(low):
        if authed:
            out.append(Indicator("bank_change_request", "content", "medium", 6,
                "Banka/odeme bilgisi degisikligi bildirimi (gonderen dogrulanmis: DMARC pass)",
                "Hesap bilgisi degisikligi bildiriliyor. Gonderen dogrulanmis oldugu "
                "icin dusuk agirlik; yine de degisikligi bildiginiz bir numaradan "
                "telefonla teyit edin."))
        else:
            out.append(Indicator("bank_change_request", "content", "high", 12,
                "Banka/odeme bilgisi degisikligi bildirimi, gonderen dogrulanmamis",
                "Tedarikci dolandiriciliginin kendisi: fatura gercektir, hesap "
                "numarasi degildir. Odeme yapmadan once bildiginiz bir numaradan "
                "telefonla teyit edin."))

    # --- business e-mail compromise ---
    money = _MONEY.search(low)
    pretext = _PRETEXT.search(low)
    if money and pretext and length <= _BEC_MAX_CHARS and (from_free or reply_elsewhere):
        how = ("ucretsiz posta adresi " + email.from_domain if from_free
               else "yanit baska domaine gidiyor (" + reply_rdom + ")")
        out.append(Indicator("bec_request", "content", "high", 14,
            "Odeme talebi ('" + money.group(0).strip() + "') + bahane ('"
            + pretext.group(0).strip() + "'), " + how,
            "Yonetici/is ortagi taklidiyle para transferi isteyen kisa not (BEC). "
            "Link ya da ek tasimaz; tek savunma talebi baska bir kanaldan teyit etmektir."))

    # --- one of our own executives, from somewhere that is not us ---
    own = ctx.get("own_domains", set())
    shown = set(re.findall(r"[a-z0-9]+", skeleton(email.from_display or "")))
    if shown and from_rdom and from_rdom not in own:
        for name in ctx.get("vip_names", ()):
            tokens = re.findall(r"[a-z0-9]+", ascii_fold(name))
            if len(tokens) >= 2 and set(tokens) <= shown:
                out.append(Indicator("vip_impersonation", "content", "high", 18,
                    "Gonderen adi '" + name + "' (vip_names.txt) ama adres "
                    + (email.from_addr or "?") + " - kurum domaini degil",
                    "Yoneticinin adi, kurumun disindaki bir adresten kullaniliyor. "
                    "Kisisel adresinden gercekten yaziyor olabilir; para, sifre ya da "
                    "dosya isteyen her talebi baska kanaldan teyit edin."))
                break

    # --- a reply to nothing ---
    headers = getattr(email, "headers", {}) or {}
    if (_REPLY_SUBJECT.match(ascii_fold(email.subject or ""))
            and not headers.get("in-reply-to") and not headers.get("references")
            and getattr(email, "header_source", "rfc822") != "mapi"):
        out.append(Indicator("fake_reply_subject", "content", "low", 6,
            "Konu 'RE:' ile basliyor ama mail hicbir mesaja yanit degil "
            "(In-Reply-To / References yok)",
            "Suregelen bir yazismanin parcasi gibi gorunmek icin konuya elle 'RE:' "
            "eklenir. Bazi istemciler bu basliklari silebilir; tek basina kanit degildir."))
    return out
