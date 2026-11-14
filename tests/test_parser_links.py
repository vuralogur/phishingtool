"""What the parser must see: every body part, every link spelling, every IP form.

Each test here is an evasion that used to work - the reader's mail client showed
a link or a form while the analyzer saw nothing at all.
"""
from email.message import EmailMessage

import pytest

from detector import analyzer, iocs, parser
from detector.checks import html_forensics, urls
from detector.util import canonical_ip, is_ip, strip_url_noise


def _html_mail(html, plain=None):
    m = EmailMessage()
    m["From"] = "Bilgi <info@randomshop.example>"
    m["To"] = "user@victim.example"
    m["Subject"] = "Bilgilendirme"
    if plain is None:
        m.set_content(html, subtype="html")
    else:
        m.set_content(plain)
        m.add_alternative(html, subtype="html")
    return parser.parse_bytes(m.as_bytes())


def _hrefs(email):
    return [l.href for l in email.links]


def _ids(email):
    return {i.id for i in analyzer.analyze(email).indicators}


# ---------------------------------------------------------------------------
# Every body part is analyzed, not just the first one
# ---------------------------------------------------------------------------

def test_second_html_part_is_not_a_blind_spot():
    """Decoy HTML first, the real page last - clients render the last one."""
    m = EmailMessage()
    m["From"] = "Bilgi <info@randomshop.example>"
    m["Subject"] = "Bilgilendirme"
    m.set_content("duz metin")
    m.add_alternative("<p>Merhaba, bulten.</p>", subtype="html")
    m.add_alternative(
        "<form action='https://evil.tk/post.php'><input type='password'></form>"
        "<a href='http://185.10.10.10/login'>giris</a>", subtype="html")
    email = parser.parse_bytes(m.as_bytes())

    assert "bulten" in email.html_body and "password" in email.html_body
    assert "http://185.10.10.10/login" in _hrefs(email)
    ids = _ids(email)
    assert {"form_external_action", "html_password_input", "ip_url"} <= ids
    assert analyzer.analyze(email).verdict in ("high", "critical")


def test_every_plain_text_part_is_read():
    m = EmailMessage()
    m["From"] = "a@x.example"
    m["Subject"] = "t"
    m.make_mixed()
    for body in ("ilk parca", "ikinci parca http://185.10.10.10/a"):
        part = EmailMessage()
        part.set_content(body)
        m.attach(part)
    email = parser.parse_bytes(m.as_bytes())
    assert "ilk parca" in email.text_body and "ikinci parca" in email.text_body
    assert "http://185.10.10.10/a" in _hrefs(email)


def test_single_part_body_is_unchanged():
    email = parser.parse_text(
        "From: a@x.example\r\nContent-Type: text/html\r\n\r\n<p>merhaba</p>")
    assert email.html_body.strip() == "<p>merhaba</p>"
    assert email.text_body == ""


# ---------------------------------------------------------------------------
# href spellings a browser follows
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("https://example.com/a", "https://example.com/a"),          # untouched
    ("HTTP://Example.com/a", "http://Example.com/a"),
    (" https://example.com/a ", "https://example.com/a"),        # padding
    ("ht\ntps://exa\tmple.com/a", "https://example.com/a"),      # tab/newline
    ("//example.com/a", "https://example.com/a"),                # scheme-relative
    ("\\\\example.com/a", "https://example.com/a"),
    ("https:\\\\example.com\\a", "https://example.com/a"),       # backslashes
    ("https:/example.com/a", "https://example.com/a"),
    ("https:example.com/a", "https://example.com/a"),
    ("https://example.com/a?next=c:\\x", "https://example.com/a?next=c:\\x"),
    ("mailto:a@example.com", ""),
    ("/relative/path", ""),
    ("#top", ""),
    ("javascript:void(0)", ""),
    ("https://", ""),
    ("", ""),
])
def test_normalize_href(raw, expected):
    assert parser.normalize_href(raw) == expected


def test_link_spellings_reach_the_url_checks():
    email = _html_mail(
        "<a href='//185.10.10.10/login'>a</a>"
        "<a href=' https://185.10.10.11/login'>b</a>"
        "<a href='https:\\\\185.10.10.12/login'>c</a>")
    assert _hrefs(email) == ["https://185.10.10.10/login",
                             "https://185.10.10.11/login",
                             "https://185.10.10.12/login"]
    assert "ip_url" in {i.id for i in urls.run(email, ctx=analyzer.build_context())}


def test_area_form_and_formaction_targets_are_links():
    email = _html_mail(
        "<map><area href='http://185.10.10.13/x'></map>"
        "<form action='http://185.10.10.14/post'></form>"
        "<button formaction='http://185.10.10.15/x'>Gonder</button>"
        "<input type='submit' formaction='http://185.10.10.16/x'>")
    assert _hrefs(email) == ["http://185.10.10.13/x", "http://185.10.10.14/post",
                             "http://185.10.10.15/x", "http://185.10.10.16/x"]
    assert all(l.text == "" for l in email.links)


def test_formaction_counts_as_an_external_form_post():
    email = _html_mail("<form><button formaction='http://collect.evil-site.com/x'>"
                       "Gonder</button></form>")
    assert "form_external_action" in {i.id for i in html_forensics.run(email)}


def test_unclosed_anchor_is_still_a_link():
    email = _html_mail("<p><a href='http://185.10.10.10/a'>tikla<p>son")
    assert _hrefs(email) == ["http://185.10.10.10/a"]


def test_anchor_text_and_duplicates_are_kept_for_anchors():
    email = _html_mail("<a href='https://a.example/x'>bir</a>"
                       "<a href='https://a.example/x'>iki</a>")
    assert [(l.text, l.href) for l in email.links] == [
        ("bir", "https://a.example/x"), ("iki", "https://a.example/x")]


# ---------------------------------------------------------------------------
# Links that carry code or a whole page instead of an address
# ---------------------------------------------------------------------------

def test_javascript_href_yields_its_inner_url_and_is_reported():
    email = _html_mail(
        "<a href='javascript:location=\"http://185.10.10.14/x\"'>paypal.com</a>")
    assert [(l.text, l.href) for l in email.links] == [
        ("paypal.com", "http://185.10.10.14/x")]
    ids = {i.id for i in html_forensics.run(email)}
    assert "active_content_link" in ids


def test_data_and_vbscript_links_are_reported():
    for href in ("data:text/html;base64,PGh0bWw+", " DATA:text/html,<b>x</b>",
                 "vbscript:msgbox(1)", "java\nscript:alert(1)"):
        email = _html_mail('<a href="' + href + '">ac</a>')
        ind = [i for i in html_forensics.run(email) if i.id == "active_content_link"]
        assert ind, href
        assert ind[0].technique == "T1027"


@pytest.mark.parametrize("href", [
    "javascript:void(0)", "javascript:void(0);", "javascript:;", "javascript:",
    "JavaScript: void 0", "javascript:return false;", "javascript://",
    "data:image/png;base64,iVBORw0KGgo=", "https://example.com/a", "#",
    "mailto:a@example.com", "tel:+902120000000",
])
def test_placeholder_and_ordinary_links_are_not_active_content(href):
    email = _html_mail("<a href='" + href + "'>link</a><area href='" + href + "'>")
    assert "active_content_link" not in {i.id for i in html_forensics.run(email)}


# ---------------------------------------------------------------------------
# URLs typed as text, without a scheme
# ---------------------------------------------------------------------------

def test_bare_urls_in_plain_text_are_links():
    email = parser.parse_text(
        "From: a@x.example\r\nSubject: t\r\n\r\n"
        "Giris icin: www.paypa1.com/login veya paypa1.com/giris adresine gidin. "
        "Ayrica www.example.org.")
    assert _hrefs(email) == ["http://www.paypa1.com/login", "http://paypa1.com/giris",
                             "http://www.example.org"]
    assert "lookalike_domain" in _ids(email)


@pytest.mark.parametrize("text", [
    "Kargo Ltd.Sti firmasindan",          # not a public suffix
    "Rapor ekte: rapor.pdf",              # a file name
    "Dosya: belgeler/rapor.pdf/son",      # path, no domain
    "Iletisim: destek@example.com",       # an address, not a link
    "Bize ulasin: destek@example.com/yardim",
    "example.com",                        # bare name: no www., no path
    "ve/veya 3.5/5 puan, v1.2/api",
    "Toplanti 12.11.2026 tarihinde",
])
def test_ordinary_text_is_not_mistaken_for_a_link(text):
    email = parser.parse_text("From: a@x.example\r\nSubject: t\r\n\r\n" + text)
    assert _hrefs(email) == []


def test_url_inside_another_url_is_not_counted_twice():
    email = parser.parse_text(
        "From: a@x.example\r\nSubject: t\r\n\r\n"
        "https://example.com/r?next=www.other.example/a")
    assert _hrefs(email) == ["https://example.com/r?next=www.other.example/a"]


def test_url_in_visible_html_text_is_a_link_but_anchor_text_is_not():
    email = _html_mail(
        "<p>Adres: http://185.10.10.20/a ve www.paypa1.com/giris</p>"
        "<a href='https://example.com/x'>https://www.paypal.com/signin</a>"
        "<script>var u='http://185.10.10.21/js';</script>"
        "<style>a{background:url(http://185.10.10.22/css)}</style>")
    assert _hrefs(email) == ["https://example.com/x", "http://185.10.10.20/a",
                             "http://www.paypa1.com/giris"]


def test_same_url_in_html_and_text_part_is_listed_once():
    email = _html_mail("<a href='https://example.com/x'>ac</a>",
                       plain="Ac: https://example.com/x")
    assert _hrefs(email) == ["https://example.com/x"]


# ---------------------------------------------------------------------------
# IP hosts in every notation a browser accepts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host, expected", [
    ("192.168.1.1", "192.168.1.1"),
    ("3232235777", "192.168.1.1"),          # one decimal number
    ("0xC0A80101", "192.168.1.1"),          # hex
    ("0300.0250.01.01", "192.168.1.1"),     # octal
    ("0xC0.168.0x1.1", "192.168.1.1"),      # mixed
    ("192.168.257", "192.168.1.1"),         # last part fills two bytes
    ("192.168.1.1.", "192.168.1.1"),
    ("[2001:db8::1]", "2001:db8::1"),
    ("2001:DB8:0:0::1", "2001:db8::1"),
    ("example.com", ""),
    ("1e100.net", ""),
    ("123.com", ""),
    ("0x.com", ""),
    ("256.1.1.1", ""),                      # a byte cannot be 256
    ("1.2.3.4.5", ""),
    ("4294967296", ""),                     # one past 255.255.255.255
    ("08", ""),                             # not valid octal
    ("1_0.1.1.1", ""),
    ("", ""),
    ("localhost", ""),
])
def test_canonical_ip(host, expected):
    assert canonical_ip(host) == expected
    assert is_ip(host) is bool(expected)


def test_disguised_ip_links_are_flagged_with_the_real_address():
    email = _html_mail("<a href='http://3232235777/login'>a</a>")
    ind = [i for i in urls.run(email, ctx=analyzer.build_context()) if i.id == "ip_url"]
    assert ind and "3232235777 (= 192.168.1.1)" in ind[0].evidence

    for href in ("http://0xC0A80101/login", "http://[2001:db8::1]/x",
                 "http://0300.0250.01.01/"):
        email = _html_mail("<a href='" + href + "'>a</a>")
        assert "ip_url" in {i.id for i in urls.run(email, ctx=analyzer.build_context())}, href


def test_plain_ip_evidence_is_unchanged():
    email = _html_mail("<a href='http://185.10.10.10/login'>a</a>")
    ind = [i for i in urls.run(email, ctx=analyzer.build_context()) if i.id == "ip_url"]
    assert ind[0].evidence == "Baglanti dogrudan IP adresi: 185.10.10.10"


def test_iocs_list_disguised_ips_in_plain_notation():
    email = _html_mail("<a href='http://3232235777/login'>a</a>"
                       "<a href='http://[2001:db8::1]/x'>b</a>"
                       "<a href='//185.10.10.10/y'>c</a>")
    found = iocs.collect(email)
    assert {"192.168.1.1", "2001:db8::1", "185.10.10.10"} <= set(found.ips)
    assert "3232235777" not in found.domains
    # The URL itself is reported as the mail wrote it.
    assert "http://3232235777/login" in found.urls


def test_strip_url_noise():
    assert strip_url_noise(" \t https://x \r\n") == "https://x"
    assert strip_url_noise("ht\ntps://x") == "https://x"
    assert strip_url_noise(None) == ""
