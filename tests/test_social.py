"""Payload-less social engineering, organisation protection, and the small
URL / header signals added with them - each from both sides.

The findings here are conjunctions (wording + shape + who vouches for the
sender), so most of this file is the mails that share the wording and must NOT
be flagged: an honest invoice with a phone number, a manager asking for a
payment from the company domain, a friend on Gmail.
"""
import json
from email.message import EmailMessage

import pytest

from detector import analyzer, bench, config, parser, report
from detector.checks import social
from detector.scoring import SOFT_IDS, STACK_IDS

CTX = analyzer.build_context(config=config.DEFAULTS)
RECEIVED = ("from mail.example.net ([93.184.216.34]) by mx.alici.com with ESMTPS; "
            "Mon, 2 Nov 2026 10:00:00 +0300")
PASS = ("mx.alici.com; spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; "
        "dmarc=pass header.from={d}")


def build(frm, subject, text="", html=None, reply_to=None, auth=None, headers=()):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = "ali@alici.com"
    m["Subject"] = subject
    if reply_to:
        m["Reply-To"] = reply_to
    if auth:
        m["Authentication-Results"] = auth
    m["Received"] = RECEIVED
    for key, value in headers:
        m[key] = value
    m.set_content(text or "merhaba")
    if html:
        m.add_alternative(html, subtype="html")
    return parser.parse_bytes(m.as_bytes())


def analyze(email, ctx=CTX):
    return analyzer.analyze(email, ctx=ctx)


def ids(result):
    return {i.id for i in result.indicators}


# -- callback phishing -------------------------------------------------------

NORTON = ("Your Norton 360 subscription has been renewed for another year. "
          "$349.99 has been charged to your card. If you did not authorize this "
          "transaction, call our billing team at +1 (808) 555-0199 to cancel.")
ABONELIK = ("Aboneliginiz yenilenmistir. 1.299,00 TL kartinizdan cekilecektir. "
            "Islemi siz yapmadiysaniz iptal icin 0850 555 44 33 numarali hatti arayin.")


@pytest.mark.parametrize("frm, body", [
    ("Billing <billing.dept4471@gmail.com>", NORTON),
    ("Destek <abonelik.destek@outlook.com>", ABONELIK),
])
def test_fake_renewal_with_a_number_to_call_from_freemail(frm, body):
    r = analyze(build(frm, "Order confirmation #INV-88213", body))
    assert "callback_phishing" in ids(r)
    assert r.verdict == "medium"            # 14 hard: was "low" with no finding
    assert "callback_phishing" not in SOFT_IDS


def test_evidence_shows_the_number():
    r = analyze(build("Billing <billing.dept4471@gmail.com>", "Invoice", NORTON))
    evidence = next(i.evidence for i in r.indicators if i.id == "callback_phishing")
    assert "555-0199" in evidence and "gmail.com" in evidence


def test_brand_named_by_an_unauthenticated_stranger():
    body = NORTON.replace("Norton 360", "PayPal")
    r = analyze(build("Billing <billing@invoice-center.net>", "Your PayPal order", body))
    assert "callback_phishing" in ids(r)


def test_the_same_notice_from_an_authenticated_business_is_left_alone():
    body = NORTON.replace("Norton 360", "PayPal")
    r = analyze(build("Billing <billing@invoice-center.net>", "Your order", body,
                      auth=PASS.format(d="invoice-center.net")))
    assert "callback_phishing" not in ids(r)


@pytest.mark.parametrize("body", [
    # an honest invoice: amount, phone, even "iade" - but nobody is impersonated
    "Faturaniz ektedir. Tutar 1.200,00 TL. Iade ve iptal kosullari sozlesmededir. "
    "Sorulariniz icin 0212 555 44 33 numarali telefondan arayabilirsiniz.",
    "Siparisiniz kargoya verildi. Odeme tutari 450 TL. Iptal icin sitemizi ziyaret edin.",
])
def test_ordinary_business_invoice_is_not_callback_phishing(body):
    r = analyze(build("Muhasebe <fatura@tedarikci.com.tr>", "Kasim faturaniz", body))
    assert "callback_phishing" not in ids(r)


@pytest.mark.parametrize("body", [
    NORTON.replace("call our billing team at +1 (808) 555-0199 to cancel",
                   "visit your account to cancel"),                  # no phone
    NORTON.replace("$349.99 has been", "An amount has been"),         # no amount
    "Selam, yarin musait misin? Beni 0532 555 44 33 numarasindan ara.",   # a friend
    "Siparis numaraniz 1234567890. Odeme 100 TL. Iptal icin bizi arayin.",  # not a phone
])
def test_freemail_alone_is_not_enough(body):
    r = analyze(build("Ayse <ayse.k@gmail.com>", "Merhaba", body))
    assert "callback_phishing" not in ids(r)


@pytest.mark.parametrize("text, expected", [
    ("ara +90 (212) 555 44 33 hemen", ["+90 (212) 555 44 33"]),
    ("call 1-888-555-0199 now", ["1-888-555-0199"]),
    ("hat: 444 0 333", ["444 0 333"]),
    ("siparis 1234567890", []),                      # bare digits
    ("tarih 02.11.2026 10:00", []),                  # a date
    ("iban TR12 0006 2000 1234 5678 9012 34", []),   # too many digits
    ("tutar 1.299,00 TL", []),
])
def test_phone_number_recognition(text, expected):
    assert [n for _, n in social._phones(text)] == expected


# -- changed bank details ----------------------------------------------------


@pytest.mark.parametrize("body", [
    "Banka hesap bilgilerimiz degismistir. Bundan sonraki odemeleri asagidaki hesaba yapiniz.",
    "IBAN numaramiz guncellenmistir, lutfen kayitlarinizi duzeltin.",
    "Please note that our bank details have changed. Use the account below.",
    "Attached are our updated banking information for all future invoices.",
    "Yeni banka hesap bilgilerimiz ektedir.",
])
def test_changed_bank_details_from_an_unauthenticated_sender(body):
    r = analyze(build("Muhasebe <muhasebe@tedarikci.com.tr>", "Hesap bilgisi", body))
    hit = [i for i in r.indicators if i.id == "bank_change_request"]
    assert hit and hit[0].weight == 12
    assert r.verdict == "medium"


def test_authenticated_sender_gets_the_low_weight():
    r = analyze(build("Muhasebe <muhasebe@tedarikci.com.tr>", "Hesap bilgisi",
                      "Banka hesap bilgilerimiz degismistir.",
                      auth=PASS.format(d="tedarikci.com.tr")))
    hit = [i for i in r.indicators if i.id == "bank_change_request"]
    assert hit and hit[0].weight == 6 and r.verdict == "low"


@pytest.mark.parametrize("body", [
    "Banka hesap bilgilerimiz asagidadir: IBAN TR00 0000 0000 0000 0000 0000 00",
    "Hesap bilgileriniz ile yeni siparis olusturabilirsiniz.",
    "Odeme icin IBAN: TR00 0000 0000. Tesekkurler.",
    "Sifreniz degistirildi. Bu islemi siz yapmadiysaniz bize ulasin.",
])
def test_stating_or_mentioning_an_account_is_not_a_change_notice(body):
    r = analyze(build("Muhasebe <muhasebe@tedarikci.com.tr>", "Bilgi", body))
    assert "bank_change_request" not in ids(r)


# -- business e-mail compromise ----------------------------------------------

BEC_TR = ("Musait misin? Acil bir havale yapmamiz gerekiyor. Su an toplantidayim, "
          "arayamam. Detaylari buradan yazacagim.")
BEC_EN = ("Are you at your desk? I need you to process a payment for a vendor today. "
          "I'm in a meeting and can't talk, just reply here.")


def test_payment_request_with_a_pretext_from_freemail():
    r = analyze(build("Ahmet Yilmaz <ahmet.yilmaz.ofis@gmail.com>", "Acil", BEC_TR))
    assert "bec_request" in ids(r) and r.verdict == "medium"


def test_payment_request_whose_reply_goes_elsewhere_is_high():
    r = analyze(build("Genel Mudur <gm@sirket-ornek.com.tr>", "Quick task", BEC_EN,
                      reply_to="gm@sirket-ornek-mail.com"))
    assert {"bec_request", "from_replyto_mismatch"} <= ids(r)
    assert r.verdict == "high"


@pytest.mark.parametrize("frm, body, reply_to", [
    # the same words from the company's own address, replies staying there
    ("Genel Mudur <gm@sirket-ornek.com.tr>", BEC_EN, None),
    ("Genel Mudur <gm@sirket-ornek.com.tr>", BEC_TR, "gm@sirket-ornek.com.tr"),
    # freemail, a pretext, no money
    ("Ayse <ayse.k@gmail.com>", "Musait misin? Aksam yemege gidelim mi?", None),
    # freemail, money, no pretext
    ("Ayse <ayse.k@gmail.com>", "Havale yaptim, dekont ektedir. Iyi calismalar.", None),
    # freemail, both phrases, but a long ordinary mail rather than a short note
    ("Bulten <haber.bulteni@gmail.com>", BEC_TR + " Lorem ipsum dolor sit amet. " * 80, None),
])
def test_wording_without_the_rest_is_not_bec(frm, body, reply_to):
    r = analyze(build(frm, "Merhaba", body, reply_to=reply_to))
    assert "bec_request" not in ids(r)


# -- organisation protection -------------------------------------------------


@pytest.fixture
def org(tmp_path):
    (tmp_path / "own_domains.txt").write_text("# bizim\nsirketim.com.tr\n", encoding="utf-8")
    (tmp_path / "vip_names.txt").write_text("Ahmet Yılmaz\nAyse\n", encoding="utf-8")
    return analyzer.build_context(data_dir=tmp_path, config=config.DEFAULTS)


def test_bundled_org_files_are_empty_so_nothing_changes():
    assert CTX["own_domains"] == set() and CTX["vip_names"] == []
    assert len(CTX["free_hosting"]) > 20


def test_own_domains_are_protected_like_a_brand(org):
    assert org["brands"]["sirketim"] == {"sirketim.com.tr"}
    assert org["free_hosting"]                       # falls back to the bundled list


@pytest.mark.parametrize("display", ["Ahmet Yilmaz", "AHMET YILMAZ", "Ahmet Yılmaz",
                                     '"Yilmaz, Ahmet"', "Dr. Ahmet Yilmaz (GM)",
                                     "Аhmet Yilmaz"])                 # Cyrillic A
def test_executive_name_from_outside_the_organisation(org, display):
    r = analyze(build(display + " <ahmet.yilmaz.gm@gmail.com>", "Merhaba", "Selam."), org)
    assert "vip_impersonation" in ids(r)
    assert r.verdict == "medium"


@pytest.mark.parametrize("frm", [
    "Ahmet Yilmaz <ahmet.yilmaz@sirketim.com.tr>",        # the real one
    "Ahmet Kaya <ahmet.kaya@gmail.com>",                  # a namesake by first name
    "Ayse <ayse@gmail.com>",                              # single-word entries are ignored
    "Mehmet Demir <mehmet@example.com>",
])
def test_everyone_else_is_not_a_vip(org, frm):
    assert "vip_impersonation" not in ids(analyze(build(frm, "Merhaba", "Selam."), org))


def test_no_vip_list_no_finding():
    r = analyze(build("Ahmet Yilmaz <ahmet.yilmaz.gm@gmail.com>", "Merhaba", "Selam."))
    assert "vip_impersonation" not in ids(r)


def test_lookalike_of_an_own_domain_is_caught(org):
    r = analyze(build("Muhasebe <muhasebe@sirketlm.com.tr>", "Fatura", "Ekte."), org)
    assert "lookalike_domain" in ids(r)


def test_unauthenticated_mail_claiming_an_own_domain_is_a_spoof(org):
    r = analyze(build("IK <ik@sirketim.com.tr>", "Bordro", "Ekte.",
                      auth="mx.alici.com; spf=fail smtp.mailfrom=sirketim.com.tr; dmarc=fail"),
                org)
    assert "brand_domain_spoof" in ids(r)


# -- a reply to nothing, two senders -----------------------------------------


@pytest.mark.parametrize("subject", ["RE: Fatura", "Re: Re: teklif", "YNT: Toplanti",
                                     "Cevap: siparis"])
def test_reply_subject_without_a_thread(subject):
    r = analyze(build("Ali <ali@example.com>", subject, "Ekteki belgeye bakar misin?"))
    assert "fake_reply_subject" in ids(r)
    assert "fake_reply_subject" in SOFT_IDS and "fake_reply_subject" not in STACK_IDS
    assert r.verdict == "low"


@pytest.mark.parametrize("subject, headers", [
    ("RE: Fatura", [("In-Reply-To", "<abc@example.com>")]),
    ("RE: Fatura", [("References", "<abc@example.com>")]),
    ("Rezervasyon onayi", []),
    ("Fatura", []),
])
def test_real_replies_and_ordinary_subjects(subject, headers):
    r = analyze(build("Ali <ali@example.com>", subject, "Merhaba", headers=headers))
    assert "fake_reply_subject" not in ids(r)


def test_two_different_from_headers():
    raw = ("From: Banka <guvenlik@banka-ornek.com.tr>\r\n"
           "From: Baska Biri <x@saldirgan-ornek.net>\r\n"
           "To: ali@alici.com\r\nSubject: Bilgi\r\n\r\nMerhaba")
    r = analyzer.analyze(parser.parse_text(raw), ctx=CTX)
    hit = [i for i in r.indicators if i.id == "multiple_from_headers"]
    assert hit and "saldirgan-ornek.net" in hit[0].evidence
    assert r.verdict == "medium"


def test_a_repeated_identical_from_is_only_sloppy():
    raw = ("From: Ali <ali@example.com>\r\nFrom: Ali <ali@example.com>\r\n"
           "Subject: Bilgi\r\n\r\nMerhaba")
    assert "multiple_from_headers" not in ids(analyzer.analyze(parser.parse_text(raw), ctx=CTX))


# -- URL signals -------------------------------------------------------------


def link_mail(href, frm="Bildirim <bilgi@duyuru-servis.com>"):
    return build(frm, "Bilgi", "Bakiniz.", html='<p>Bakiniz: <a href="' + href + '">tikla</a></p>')


@pytest.mark.parametrize("href", [
    "https://giris-dogrula.pages.dev/hesap",
    "https://a1b2c3.ngrok-free.app/login",
    "https://bafybeigdyrzt.ipfs.dweb.link/index.html",
    "https://musteri-destek.web.app/",
])
def test_free_hosting_and_tunnel_links(href):
    r = analyze(link_mail(href))
    assert "free_hosting_url" in ids(r)
    assert "free_hosting_url" in SOFT_IDS and "free_hosting_url" in STACK_IDS


def test_one_free_hosting_link_alone_stays_low():
    r = analyze(link_mail("https://giris-dogrula.pages.dev/hesap"))
    assert r.breakdown.hard == 0 and r.verdict == "low"     # one carrier signal


@pytest.mark.parametrize("href", ["https://github.io/", "https://vercel.app/pricing",
                                  "https://www.example.com/pages.dev/x",
                                  "https://notpages.dev.example.com/"])
def test_the_service_itself_and_lookalike_strings_are_not_free_hosting(href):
    assert "free_hosting_url" not in ids(analyze(link_mail(href)))


def test_senders_own_free_hosted_site_is_first_party():
    r = analyze(link_mail("https://benimsitem.netlify.app/blog",
                          frm="Ben <ben@benimsitem.netlify.app>"))
    assert "free_hosting_url" not in ids(r)


def test_free_hosting_plus_a_shortener_is_a_stack():
    r = analyze(build("Bildirim <bilgi@duyuru-servis.com>", "Bilgi", "x",
                      html='<a href="https://giris.pages.dev/x">a</a>'
                           '<a href="https://bit.ly/3xYz">b</a>'))
    assert r.verdict == "medium" and r.breakdown.reason == "soft_stack"


@pytest.mark.parametrize("href", [
    "https://evil-site.net/paypal.com/login",
    "https://evil-site.net/secure/www.paypal.com/",
    "https://evil-site.net/x/paypal.com",
])
def test_brand_domain_in_the_path_of_another_host(href):
    r = analyze(link_mail(href))
    assert "brand_in_path" in ids(r)
    assert "brand_in_path" in SOFT_IDS and "brand_in_path" in STACK_IDS


@pytest.mark.parametrize("href", [
    "https://www.paypal.com/paypal.com/yardim",          # the brand's own host
    "https://example.org/go?u=paypal.com",               # query, not path
    "https://example.org/blog/paypal-comparison",        # a word, not the domain
    "https://example.org/notpaypal.com.html",
])
def test_brand_named_elsewhere_in_a_url_is_not_brand_in_path(href):
    assert "brand_in_path" not in ids(analyze(link_mail(href)))


# -- keywords split by markup ------------------------------------------------


@pytest.mark.parametrize("html", [
    "<p>Lutfen pass<span></span>word bilginizi girin.</p>",
    "<p>Hesabiniz icin sif&#8203;renizi dogrulayin.</p>",
    "<p>Kart num<b></b>arasi ve CV<i></i>V gerekli.</p>",
])
def test_keyword_split_by_tags_or_zero_width_characters_is_still_read(html):
    r = analyze(build("Destek <destek@duyuru-servis.com>", "Bilgi", "x", html=html))
    assert "credential_request" in ids(r)


def test_block_tags_still_separate_words():
    html = "<table><tr><td>compass</td><td>word list</td></tr></table>"
    r = analyze(build("Destek <destek@duyuru-servis.com>", "Bilgi", "x", html=html))
    assert "credential_request" not in ids(r)


# -- bench: per-indicator breakdown ------------------------------------------


def write_corpus(root):
    (root / "phish").mkdir()
    (root / "ham").mkdir()
    phish = ("From: Destek <destek@hesap-islem.xyz>\r\nSubject: ACIL\r\n"
             "Content-Type: text/html\r\n\r\n"
             '<a href="https://bit.ly/3xYz">sifrenizi girin</a>')
    ham = ("From: Ali <ali@example.com>\r\nSubject: Toplanti\r\n\r\n"
           "Yarin 10:00. Notlar: https://bit.ly/notlar")
    (root / "phish" / "a.eml").write_text(phish, encoding="utf-8")
    (root / "phish" / "b.eml").write_text(phish.replace("ACIL", "Bilgi"), encoding="utf-8")
    (root / "ham" / "c.eml").write_text(ham, encoding="utf-8")
    (root / "ham" / "d.eml").write_text("From: Veli <veli@example.com>\r\nSubject: x\r\n\r\nSelam",
                                        encoding="utf-8")


def test_indicator_stats_count_mails_per_label(tmp_path):
    write_corpus(tmp_path)
    result = bench.run(tmp_path, ctx=CTX)
    stats = {row["id"]: row for row in result.indicator_stats()}
    assert stats["url_shortener"] == {"id": "url_shortener", "kind": "soft", "phish": 2,
                                      "ham": 1, "phish_rate": 1.0, "ham_rate": 0.5}
    assert stats["credential_request"]["kind"] == "hard"
    assert stats["credential_request"]["ham"] == 0
    # worst offenders (most ham hits) first
    ham_hits = [row["ham"] for row in result.indicator_stats()]
    assert ham_hits == sorted(ham_hits, reverse=True)


def test_indicator_stats_are_in_both_outputs(tmp_path):
    write_corpus(tmp_path)
    result = bench.run(tmp_path, ctx=CTX)
    data = json.loads(report.bench_to_json(result))
    assert {row["id"] for row in data["indicators"]} >= {"url_shortener", "credential_request"}
    text = report._bench_plain(result)
    assert "Gosterge kirilimi" in text and "url_shortener" in text
