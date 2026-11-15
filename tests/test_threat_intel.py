"""Threat-list matches and domain age, each from both sides.

A block list is somebody else's judgement: the tests that matter most are the
mails that must NOT be condemned by one - a link to a brand's own site, a
shortener, the front door of a hosting service, a different page on a host
that only shares an address with a listed one.
"""
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import pytest

from detector import analyzer, config, feeds, mitre, parser, rdap
from detector.checks import threat_intel
from detector.scoring import SOFT_IDS, STACK_IDS

RECEIVED = ("from mail.example.net ([93.184.216.34]) by mx.alici.com with ESMTPS; "
            "Mon, 2 Nov 2026 10:00:00 +0300")
PASS = ("mx.alici.com; spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; "
        "dmarc=pass header.from={d}")
SENDER = "Bulten <bulten@haber-sitesi-ornek.com>"


def build(link=None, frm=SENDER, reply_to=None, auth=None, text="merhaba"):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = "ali@alici.com"
    m["Subject"] = "Haftalik ozet"
    if reply_to:
        m["Reply-To"] = reply_to
    if auth:
        m["Authentication-Results"] = auth
    m["Received"] = RECEIVED
    m.set_content(text)
    if link:
        m.add_alternative('<p>Ayrintilar <a href="' + link + '">burada</a>.</p>',
                          subtype="html")
    return parser.parse_bytes(m.as_bytes())


def context(*entries, source="openphish", fetched=None):
    ctx = analyzer.build_context(config=config.DEFAULTS, feeds_dir=False)
    fs = feeds.FeedSet()
    for e in entries:
        assert fs.add(e, source)
    fs.meta.append(feeds.FeedInfo(
        source=source, path="(test)", entries=len(entries),
        fetched=fetched or datetime.now(timezone.utc)))
    ctx["feeds"] = fs
    return ctx


def analyze(email, ctx, online=False):
    return analyzer.analyze(email, online=online, ctx=ctx)


def found(result, id_):
    return [i for i in result.indicators if i.id == id_]


def ids(result):
    return {i.id for i in result.indicators}


# -- threat lists ------------------------------------------------------------

def test_no_lists_no_finding_and_the_same_result_as_before():
    mail = build("https://evil-ornek.com/login")
    plain = analyzer.analyze(mail, ctx=analyzer.build_context(config=config.DEFAULTS))
    empty = analyze(mail, context())
    assert not ids(plain) & {"threat_feed_hit", "threat_feed_neighbor"}
    assert (empty.verdict, empty.score) == (plain.verdict, plain.score)
    assert plain.verdict == "low"


@pytest.mark.parametrize("entry, link, what", [
    ("http://evil-ornek.com/login", "https://evil-ornek.com/login", "tam adres"),
    ("http://evil-ornek.com/", "https://evil-ornek.com/any/page?x=1", "evil-ornek.com - OpenPhish"),
    ("evil-ornek.com", "https://login.evil-ornek.com/x", "domain evil-ornek.com"),
    ("kotu.pages.dev", "https://kotu.pages.dev/giris", "kotu.pages.dev - OpenPhish"),
    ("192.168.1.1", "http://3232235777/a", "OpenPhish"),
])
def test_listed_link_is_a_hard_hit(entry, link, what):
    result = analyze(build(link), context(entry))
    (hit,) = found(result, "threat_feed_hit")
    assert what in hit.evidence and "OpenPhish listesinde" in hit.evidence
    assert hit.weight == 25 and hit.technique == ""
    assert result.verdict in ("high", "critical")
    assert "threat_feed_hit" not in SOFT_IDS


def test_evidence_names_the_list_and_its_date():
    when = datetime(2026, 11, 15, 9, 0, tzinfo=timezone.utc)
    ctx = context("evil-ornek.com", source="usom", fetched=when)
    ctx["feeds"].info("usom").fetched = datetime.now(timezone.utc)   # fresh
    (hit,) = found(analyze(build("https://evil-ornek.com/"), ctx), "threat_feed_hit")
    assert "USOM listesinde (liste tarihi " in hit.evidence
    assert "gun eski" not in hit.evidence


def test_a_stale_list_still_matches_and_says_how_old_it_is():
    old = datetime.now(timezone.utc) - timedelta(days=40)
    (hit,) = found(analyze(build("https://evil-ornek.com/"),
                           context("evil-ornek.com", fetched=old)), "threat_feed_hit")
    assert "40 gun eski" in hit.evidence and "feeds update" in hit.evidence


def test_a_custom_list_is_named_by_its_file():
    (hit,) = found(analyze(build("https://evil-ornek.com/"),
                           context("evil-ornek.com", source="kurum")), "threat_feed_hit")
    assert "kurum listesinde" in hit.evidence


def test_one_finding_however_many_links_match():
    m = build("https://evil-ornek.com/a", text="https://evil-ornek.com/b https://evil2-ornek.com/")
    result = analyze(m, context("evil-ornek.com", "evil2-ornek.com"))
    assert len(found(result, "threat_feed_hit")) == 1


def test_link_inside_an_attachment_says_where_it_came_from():
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = SENDER, "ali@alici.com", "Fatura"
    m["Received"] = RECEIVED
    m.set_content("ekte")
    m.add_attachment(b'<html><a href="https://evil-ornek.com/login">ac</a></html>',
                     maintype="text", subtype="html", filename="fatura.html")
    result = analyze(parser.parse_bytes(m.as_bytes()), context("evil-ornek.com"))
    (hit,) = found(result, "threat_feed_hit")
    assert "fatura.html" in hit.evidence


def test_another_page_on_the_same_host_is_soft():
    result = analyze(build("https://evil-ornek.com/kit/other.php"),
                     context("http://evil-ornek.com/kit/login.php"))
    assert not found(result, "threat_feed_hit")
    (near,) = found(result, "threat_feed_neighbor")
    assert near.weight == 10 and "baska bir adres" in near.evidence
    assert "threat_feed_neighbor" in SOFT_IDS and "threat_feed_neighbor" not in STACK_IDS
    assert result.verdict == "low"          # soft alone carries no verdict


@pytest.mark.parametrize("entry, link", [
    # A brand's own site, listed wholesale by a careless feed.
    ("http://google.com/", "https://google.com/search?q=x"),
    ("google.com", "https://docs.google.com/document/d/1"),
    # One form on a brand's host is listed; a different form is not a neighbour.
    ("https://docs.google.com/forms/d/KOTU/viewform", "https://docs.google.com/forms/d/IYI/viewform"),
    # A shortener: another short link says nothing about this one.
    ("https://bit.ly/3kotu", "https://bit.ly/3iyi"),
    ("http://bit.ly/", "https://bit.ly/3iyi"),
    # The front door of a hosting service is everybody.
    ("pages.dev", "https://iyi.pages.dev/"),
    ("http://pages.dev/", "https://pages.dev/"),
    # A sibling tenant.
    ("kotu.pages.dev", "https://iyi.pages.dev/"),
])
def test_shared_hosts_are_not_condemned_by_a_host_level_match(entry, link):
    result = analyze(build(link), context(entry))
    assert not ids(result) & {"threat_feed_hit", "threat_feed_neighbor"}


def test_the_exact_listed_address_counts_even_on_a_shared_host():
    form = "https://docs.google.com/forms/d/KOTU/viewform"
    assert found(analyze(build(form), context(form)), "threat_feed_hit")
    assert found(analyze(build("https://bit.ly/3kotu"), context("https://bit.ly/3kotu")),
                 "threat_feed_hit")


def test_allowlisted_and_own_domains_are_protected_too():
    ctx = context("musteri-ornek.com", "biz-ornek.com")
    ctx["allowlist"] = {"musteri-ornek.com"}
    ctx["own_domains"] = {"biz-ornek.com"}
    assert not found(analyze(build("https://musteri-ornek.com/x"), ctx), "threat_feed_hit")
    assert not found(analyze(build("https://portal.biz-ornek.com/x"), ctx), "threat_feed_hit")


def test_listed_sender_domain():
    ctx = context("evil-ornek.com", source="usom")
    (hit,) = found(analyze(build(frm="Banka <guvenlik@evil-ornek.com>"), ctx), "threat_feed_hit")
    assert hit.evidence.startswith("Gonderen domaini evil-ornek.com - USOM listesinde")
    (hit,) = found(analyze(build(reply_to="x@mail.evil-ornek.com"), ctx), "threat_feed_hit")
    assert hit.evidence.startswith("Reply-To domaini mail.evil-ornek.com")


def test_sender_is_not_listed_because_of_one_page_or_a_freemail_entry():
    # One listed page on a host does not make every mailbox there malicious ...
    assert not found(analyze(build(frm="A <a@evil-ornek.com>"),
                             context("http://evil-ornek.com/kit/login.php")), "threat_feed_hit")
    # ... and gmail.com on a list condemns nobody.
    assert not found(analyze(build(frm="Ali <ali@gmail.com>"), context("gmail.com")),
                     "threat_feed_hit")


def test_check_alone_without_a_feeds_key_in_the_context():
    assert threat_intel.run(build("https://evil-ornek.com/"), ctx={}) == []
    assert threat_intel.run(build("https://evil-ornek.com/"), ctx=None) == []


def test_ids_are_registered():
    assert {"threat_feed_hit", "threat_feed_neighbor"} <= mitre.NO_TECHNIQUE
    assert mitre.lookup("newly_registered_domain")[0] == "T1583.001"
    assert {"threat_feed_hit", "threat_feed_neighbor",
            "newly_registered_domain"} <= config.KNOWN_IDS


# -- domain age: the RDAP client ---------------------------------------------

def rdap_payload(date, action="registration"):
    return {"objectClassName": "domain", "ldhName": "X.EXAMPLE",
            "events": [{"eventAction": "last changed", "eventDate": "2026-11-01T00:00:00Z"},
                       {"eventAction": action, "eventDate": date}]}


@pytest.mark.parametrize("stamp, expected", [
    ("1995-08-14T04:00:00Z", datetime(1995, 8, 14, 4, 0, tzinfo=timezone.utc)),
    ("2026-11-10T10:00:00.123+00:00",
     datetime(2026, 11, 10, 10, 0, 0, 123000, tzinfo=timezone.utc)),
    ("2026-11-10T10:00:00", datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)),
])
def test_registration_event(stamp, expected):
    assert rdap.parse_registration(rdap_payload(stamp)) == expected
    assert rdap.parse_registration(rdap_payload(stamp, "Registration")) == expected


@pytest.mark.parametrize("payload", [
    None, [], {}, {"events": None}, {"events": ["x"]},
    rdap_payload("2026-11-10T10:00:00Z", action="expiration"),
    rdap_payload("dun"),
])
def test_no_registration_event_is_no_answer(payload):
    assert rdap.parse_registration(payload) is None


def test_lookup_sends_the_domain_only_and_asks_once(monkeypatch):
    import json
    calls = []

    def fake(url):
        calls.append(url)
        return json.dumps(rdap_payload("2026-11-10T00:00:00Z")).encode()
    monkeypatch.setattr(rdap, "_http_get", fake)

    now = datetime(2026, 11, 15, tzinfo=timezone.utc)
    assert rdap.age_days("Yeni-Site-Ornek.COM.", now) == 5
    assert rdap.age_days("yeni-site-ornek.com", now) == 5          # cached
    assert calls == ["https://rdap.org/domain/yeni-site-ornek.com"]


@pytest.mark.parametrize("answer", [
    OSError("zaman asimi"), b"<html>404</html>", b"[]", b"{}",
])
def test_lookup_failures_are_silent_and_remembered(monkeypatch, answer):
    calls = []

    def fake(url):
        calls.append(url)
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(rdap, "_http_get", fake)
    assert rdap.age_days("x-ornek.com") is None
    assert rdap.age_days("x-ornek.com") is None
    assert len(calls) == 1


@pytest.mark.parametrize("bad", [
    "", "localhost", "ali@x-ornek.com", "x-ornek.com/yol?mail=ali", "a b-ornek.com",
    "x-ornek.com?q=1", "../../etc",
])
def test_nothing_but_a_plain_domain_is_ever_sent(monkeypatch, bad):
    monkeypatch.setattr(rdap, "_http_get",
                        lambda url: pytest.fail("gonderildi: " + url))
    assert rdap.age_days(bad) is None


# -- domain age: the check ---------------------------------------------------

@pytest.fixture
def ages(monkeypatch):
    """Replace the RDAP client: {domain: age in days}; records what was asked.

    These tests run the whole analysis with online=True, which also switches on
    the live SPF/DKIM/DMARC checks - real DNS. They are stubbed out here so the
    only "network" an online test sees is the table below.
    """
    from detector.checks import auth_verify
    for name in ("_dkim_verify", "_spf_eval", "_dmarc_policy"):
        monkeypatch.setattr(auth_verify, name, lambda email: [])
    monkeypatch.delenv("VT_API_KEY", raising=False)
    asked = []

    def install(table):
        def age_days(domain, now=None):
            asked.append(domain)
            return table.get(domain)
        monkeypatch.setattr(rdap, "age_days", age_days)
        return asked
    return install


def test_online_run_without_the_stub_would_fail_loudly_not_reach_out():
    # Belt and braces for the fixture above: with nothing stubbed, the RDAP
    # helper is conftest's refusing one, so a lookup is a silent "unknown".
    assert rdap.age_days("haber-sitesi-ornek.com") is None


def test_offline_run_never_asks(ages):
    asked = ages({"haber-sitesi-ornek.com": 3, "evil-ornek.com": 3})
    result = analyze(build("https://evil-ornek.com/"), context(), online=False)
    assert asked == [] and not found(result, "newly_registered_domain")


def test_new_link_domain(ages):
    asked = ages({"evil-ornek.com": 4})
    result = analyze(build("https://login.evil-ornek.com/x"), context(), online=True)
    (new,) = found(result, "newly_registered_domain")
    assert new.weight == 12 and "evil-ornek.com 4 gun once kaydedilmis (RDAP)" in new.evidence
    assert "Link domaini" in new.evidence
    assert new.technique == "T1583.001" and "newly_registered_domain" not in SOFT_IDS
    assert result.verdict == "medium"
    assert asked == ["haber-sitesi-ornek.com", "evil-ornek.com"]      # sender first


def test_new_sender_domain(ages):
    ages({"haber-sitesi-ornek.com": 0})
    (new,) = found(analyze(build(), context(), online=True), "newly_registered_domain")
    assert new.evidence.startswith("Gonderen domaini haber-sitesi-ornek.com 0 gun once")


def test_authenticated_sender_gets_the_lower_weight(ages):
    ages({"haber-sitesi-ornek.com": 10})
    result = analyze(build(auth=PASS.format(d="haber-sitesi-ornek.com")), context(), online=True)
    (new,) = found(result, "newly_registered_domain")
    assert new.weight == 6 and "DMARC pass" in new.evidence
    assert result.verdict == "low"          # hard, but cannot carry a verdict alone


@pytest.mark.parametrize("age", [threat_intel.NEW_DOMAIN_DAYS, 400, 9000, None, -2])
def test_old_unknown_or_nonsense_age_is_no_finding(ages, age):
    ages({"haber-sitesi-ornek.com": age, "evil-ornek.com": age})
    result = analyze(build("https://evil-ornek.com/"), context(), online=True)
    assert not found(result, "newly_registered_domain")


def test_boundary_is_thirty_days(ages):
    ages({"evil-ornek.com": threat_intel.NEW_DOMAIN_DAYS - 1})
    assert found(analyze(build("https://evil-ornek.com/"), context(), online=True),
                 "newly_registered_domain")


@pytest.mark.parametrize("frm, link", [
    ("Ali <ali@gmail.com>", "https://google.com/x"),          # freemail + brand
    ("Ali <ali@gmail.com>", "https://bit.ly/3abc"),           # shortener
    ("Ali <ali@gmail.com>", "https://proje.pages.dev/"),      # free hosting tenant
    ("Ali <ali@gmail.com>", "http://93.184.216.34/x"),        # an IP has no registrar
    ("Ali <ali@gmail.com>", "http://3232235777/x"),
])
def test_domains_that_are_old_and_shared_are_never_asked_about(ages, frm, link):
    asked = ages({})
    analyze(build(link, frm=frm), context(), online=True)
    assert asked == []


def test_each_domain_is_asked_once_and_the_count_is_capped(ages):
    asked = ages({})
    links = " ".join("https://a%d.site%d-ornek.com/x https://b%d.site%d-ornek.com/y" % (i, i, i, i)
                     for i in range(12))
    analyze(build(text=links), context(), online=True)
    assert len(asked) == threat_intel.MAX_AGE_LOOKUPS
    assert len(set(asked)) == len(asked)
    assert asked[0] == "haber-sitesi-ornek.com"


def test_one_finding_for_the_first_new_domain(ages):
    ages({"haber-sitesi-ornek.com": 2, "evil-ornek.com": 1})
    result = analyze(build("https://evil-ornek.com/"), context(), online=True)
    (new,) = found(result, "newly_registered_domain")
    assert "haber-sitesi-ornek.com" in new.evidence


def test_list_hit_and_new_domain_add_up(ages):
    ages({"evil-ornek.com": 2})
    result = analyze(build("https://evil-ornek.com/login"), context("evil-ornek.com"), online=True)
    assert {"threat_feed_hit", "newly_registered_domain"} <= ids(result)
    assert result.verdict == "high"
