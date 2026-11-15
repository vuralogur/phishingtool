"""Threat lists: normalisation, parsing, the on-disk store, and `feeds update`.

Nothing here touches the network - conftest replaces the HTTP helper with one
that fails, and the tests that exercise a download install their own fake. The
other half of the promise is tested too: an analysis never downloads.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from detector import analyzer, cli, config, feeds, parser

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)


# -- url_key -----------------------------------------------------------------

@pytest.mark.parametrize("raw, key", [
    ("http://evil-ornek.com/login", "evil-ornek.com/login"),
    ("https://evil-ornek.com/login", "evil-ornek.com/login"),          # scheme
    ("https://EVIL-Ornek.COM/login", "evil-ornek.com/login"),          # host case
    ("https://www.evil-ornek.com/login", "evil-ornek.com/login"),      # www.
    ("https://evil-ornek.com/login/", "evil-ornek.com/login"),         # trailing /
    ("https://evil-ornek.com/login#top", "evil-ornek.com/login"),      # fragment
    ("https://evil-ornek.com:8443/login", "evil-ornek.com/login"),     # port
    ("https://evil-ornek.com/Login?id=7", "evil-ornek.com/Login?id=7"),  # path case kept
    ("http://evil-ornek.com/", "evil-ornek.com"),                      # whole host
    ("evil-ornek.com", "evil-ornek.com"),                              # bare domain
    ("evil-ornek.com/a/b", "evil-ornek.com/a/b"),                      # no scheme
    ("  evil-ornek.com.  ", "evil-ornek.com"),
    ("http://3232235777/x", "192.168.1.1/x"),                      # decimal IP
    ("192.168.1.1", "192.168.1.1"),
    ("http://[2001:db8::1]/x", "[2001:db8::1]/x"),
])
def test_url_key_normalises(raw, key):
    assert feeds.url_key(raw) == key
    assert feeds.url_key(key) == key        # what is stored reads back the same


@pytest.mark.parametrize("raw", [
    "", "   ", "<!doctype html>", "localhost", "mailto:ali@alici.com",
    "http://", "not a url", "javascript:void(0)",
])
def test_url_key_rejects_what_is_not_an_address(raw):
    assert feeds.url_key(raw) == ""


# -- parsers -----------------------------------------------------------------

def test_openphish_lines():
    text = "http://a-ornek.com/x\nhttps://b-ornek.com/\n\n# yorum\n"
    assert feeds.parse_url_lines(text) == ["http://a-ornek.com/x", "https://b-ornek.com/"]


@pytest.mark.parametrize("text", [
    "",
    "<!doctype html>\n<html>\n<head><title>Tasindik</title></head>\n</html>\n",
    "http://a-ornek.com/\nbu\nbir\nliste\ndegil\n",
])
def test_a_page_that_is_not_a_list_is_refused(text):
    # The old USOM address answers 200 with an HTML page; that must not be
    # written to disk as an (empty) list.
    with pytest.raises(feeds.FeedError):
        feeds.parse_url_lines(text)


URLHAUS_CSV = (
    "################################\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"3","2026-11-15 10:00:00","http://mal-ornek.com/a.exe","online","","malware_download",'
    '"exe","https://urlhaus.abuse.ch/url/3/","x"\n'
    '"4","2026-11-15 10:01:00","https://mal2-ornek.com/b,c.dll","offline","","malware_download",'
    '"dll","https://urlhaus.abuse.ch/url/4/","y"\n')


def test_urlhaus_csv_takes_the_url_column_not_the_report_link():
    assert feeds.parse_urlhaus_csv(URLHAUS_CSV) == [
        "http://mal-ornek.com/a.exe", "https://mal2-ornek.com/b,c.dll"]


def test_urlhaus_csv_without_urls_is_an_error():
    with pytest.raises(feeds.FeedError):
        feeds.parse_urlhaus_csv('{"status":401,"message":"Missing auth token"}')


def usom_page(urls, pages=1):
    return {"totalCount": len(urls), "count": len(urls), "page": 0, "pageCount": pages,
            "models": [{"id": i, "url": u, "type": "domain", "desc": "BP"}
                       for i, u in enumerate(urls)]}


def test_usom_page():
    entries, pages = feeds.parse_usom(usom_page(["a-ornek.com", "10.0.0.1", ""], pages=3))
    assert entries == ["a-ornek.com", "10.0.0.1"] and pages == 3


@pytest.mark.parametrize("payload", [None, [], {}, {"models": "x"}, "<html>"])
def test_usom_payload_of_the_wrong_shape(payload):
    with pytest.raises(feeds.FeedError):
        feeds.parse_usom(payload)


# -- FeedSet -----------------------------------------------------------------

def feedset(*entries, source="openphish"):
    fs = feeds.FeedSet()
    for e in entries:
        assert fs.add(e, source)
    return fs


def test_empty_set_is_falsy_and_finds_nothing():
    fs = feeds.FeedSet()
    assert not fs and len(fs) == 0
    assert fs.lookup("http://evil-ornek.com/") is None
    assert fs.lookup_host("evil-ornek.com") is None


def test_exact_address():
    fs = feedset("http://evil-ornek.com/login?id=1")
    assert fs
    hit = fs.lookup("https://www.evil-ornek.com/login/?id=1#x")
    assert hit.kind == "url" and hit.source == "openphish"
    # Another recipient's token is another address: same host, not the same URL.
    assert fs.lookup("https://evil-ornek.com/login?id=2").kind == "path"
    assert fs.lookup("https://baska-ornek.com/login?id=1") is None


def test_whole_host_listed_matches_every_path_on_it():
    fs = feedset("http://evil-ornek.com/")
    assert fs.lookup("https://evil-ornek.com/any/thing").kind == "host"
    assert fs.lookup_host("EVIL-ornek.com").kind == "host"


def test_registrable_domain_listed_matches_its_subdomains():
    fs = feedset("evil-ornek.com", source="usom")
    hit = fs.lookup("https://login.evil-ornek.com/x")
    assert hit.kind == "domain" and hit.entry == "evil-ornek.com" and hit.source == "usom"
    assert fs.lookup_host("mail.evil-ornek.com").kind == "domain"


def test_listed_subdomain_does_not_condemn_its_siblings():
    fs = feedset("kotu.pages.dev")
    assert fs.lookup("https://kotu.pages.dev/x").kind == "host"
    assert fs.lookup("https://iyi.pages.dev/x") is None
    assert fs.lookup("https://pages.dev/") is None


def test_other_address_on_the_same_host_is_only_a_neighbour():
    fs = feedset("http://evil-ornek.com/kit/login.php")
    assert fs.lookup("http://evil-ornek.com/kit/other.php").kind == "path"
    assert fs.lookup("http://evil-ornek.com/").kind == "path"
    # ... and the sender's domain is not "listed" because of one page on it.
    assert fs.lookup_host("evil-ornek.com") is None


def test_ip_entries_match_any_notation():
    fs = feedset("192.168.1.1", source="usom")
    assert fs.lookup("http://3232235777/a").kind == "host"
    assert fs.lookup("http://0xC0A80101/").kind == "host"


def test_first_source_keeps_the_credit():
    fs = feeds.FeedSet()
    fs.add("evil-ornek.com", "usom")
    fs.add("evil-ornek.com", "openphish")
    assert fs.lookup_host("evil-ornek.com").source == "usom"


def test_garbage_is_not_added():
    fs = feeds.FeedSet()
    assert not fs.add("<html>", "x") and not fs


# -- reading the folder ------------------------------------------------------

def test_missing_folder_is_an_empty_set(tmp_path):
    fs = feeds.load(tmp_path / "yok")
    assert not fs and fs.meta == []


def test_load_reads_header_and_entries(tmp_path):
    (tmp_path / "openphish.txt").write_text(
        "# phishingtool tehdit listesi\n# source: openphish\n"
        "# fetched: 2026-11-15T12:00:00+00:00\n# entries: 2\n"
        "evil-ornek.com\nevil2-ornek.com/login\n", encoding="utf-8")
    fs = feeds.load(tmp_path)
    assert len(fs) == 2
    info = fs.info("openphish")
    assert info.entries == 2 and info.fetched == NOW and not info.error
    assert info.age_days(NOW + timedelta(days=3)) == 3
    assert not info.stale(NOW + timedelta(days=feeds.STALE_DAYS))
    assert info.stale(NOW + timedelta(days=feeds.STALE_DAYS + 1))
    assert info.to_dict()["fetched"] == "2026-11-15T12:00:00+00:00"


def test_a_hand_written_list_is_read_too(tmp_path):
    # Notepad: BOM, CRLF, full URLs, mixed case, blank lines.
    (tmp_path / "kurum.txt").write_bytes(
        "﻿# bizim engel listemiz\r\n\r\nhttps://WWW.Kotu-ornek.com/giris/\r\n"
        "baska-kotu-ornek.com\r\n".encode("utf-8"))
    fs = feeds.load(tmp_path)
    assert fs.lookup("http://kotu-ornek.com/giris").kind == "url"
    assert fs.lookup_host("baska-kotu-ornek.com").source == "kurum"
    assert fs.info("kurum").fetched is not None      # the file's own date


def test_only_txt_files_are_lists(tmp_path):
    (tmp_path / "notlar.md").write_text("evil-ornek.com\n", encoding="utf-8")
    (tmp_path / "openphish.txt.tmp").write_text("evil-ornek.com\n", encoding="utf-8")
    assert not feeds.load(tmp_path)


def test_folder_resolution_order(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHINGTOOL_FEEDS", str(tmp_path / "env"))
    assert feeds.resolve_dir() == tmp_path / "env"
    assert feeds.resolve_dir(tmp_path / "arg") == tmp_path / "arg"
    monkeypatch.delenv("PHISHINGTOOL_FEEDS")
    assert feeds.resolve_dir() == feeds.default_dir()
    assert feeds.default_dir().parts[-2:] == ("phishingtool", "feeds")


# -- update ------------------------------------------------------------------

class FakeNet:
    """Stands in for feeds._http_get: URL prefix -> bytes (or an exception)."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        for prefix, answer in self.routes.items():
            if url.startswith(prefix):
                if isinstance(answer, Exception):
                    raise answer
                return answer(url) if callable(answer) else answer
        raise AssertionError("beklenmeyen adres: " + url)


OPENPHISH_BODY = b"http://evil-ornek.com/login\nhttps://www.evil2-ornek.com/\nhttp://evil-ornek.com/login\n"


def usom_bytes(urls, pages=1):
    return json.dumps(usom_page(urls, pages)).encode("utf-8")


@pytest.fixture
def net(monkeypatch):
    def install(routes):
        fake = FakeNet(routes)
        monkeypatch.setattr(feeds, "_http_get", fake)
        return fake
    return install


def test_update_writes_normalised_deduplicated_lists(tmp_path, net, monkeypatch):
    monkeypatch.delenv(feeds.URLHAUS_KEY_ENV, raising=False)
    net({feeds.OPENPHISH_URL: OPENPHISH_BODY,
         feeds.USOM_URL: usom_bytes(["kotu-ornek.com", "10.1.2.3"])})
    results = {r.source: r for r in feeds.update(feeds_dir=tmp_path, now=NOW)}

    assert results["openphish"].status == "ok" and results["openphish"].entries == 2
    assert results["usom"].status == "ok" and results["usom"].entries == 2
    assert results["urlhaus"].status == "skipped"
    assert feeds.URLHAUS_KEY_ENV in results["urlhaus"].message

    lines = (tmp_path / "openphish.txt").read_text(encoding="utf-8").splitlines()
    assert "# source: openphish" in lines
    assert "# fetched: 2026-11-15T12:00:00+00:00" in lines
    assert [l for l in lines if not l.startswith("#")] == ["evil-ornek.com/login", "evil2-ornek.com"]
    assert not list(tmp_path.glob("*.tmp"))            # swapped in, nothing left over
    assert not (tmp_path / "urlhaus.txt").exists()

    fs = feeds.load(tmp_path)
    assert fs.lookup("https://evil-ornek.com/login").source == "openphish"
    assert fs.lookup_host("kotu-ornek.com").source == "usom"
    assert fs.info("usom").fetched == NOW


def test_usom_is_fetched_page_by_page_for_the_asked_window(tmp_path, net):
    def pages(url):
        return usom_bytes(["a-ornek.com"] if "&page=1" in url else ["b-ornek.com"], pages=2)
    fake = net({feeds.USOM_URL: pages})
    (result,) = feeds.update(["usom"], tmp_path, days=10, now=NOW)
    assert result.status == "ok" and result.entries == 2
    assert len(fake.calls) == 2
    assert all("date_gte=2026-11-05" in u and "per-page=5000" in u for u in fake.calls)
    assert fake.calls[0].endswith("&page=1") and fake.calls[1].endswith("&page=2")


def test_usom_page_ceiling(tmp_path, net, monkeypatch):
    monkeypatch.setattr(feeds, "USOM_MAX_PAGES", 3)
    fake = net({feeds.USOM_URL: lambda url: usom_bytes(
        [url.rsplit("=", 1)[1] + "-ornek.com"], pages=10**6)})
    (result,) = feeds.update(["usom"], tmp_path, now=NOW)
    assert len(fake.calls) == 3 and result.entries == 3


def test_urlhaus_needs_a_key_and_uses_it(tmp_path, net, monkeypatch):
    monkeypatch.setenv(feeds.URLHAUS_KEY_ENV, "abc123")
    fake = net({"https://urlhaus-api.abuse.ch/": URLHAUS_CSV.encode()})
    (result,) = feeds.update(["urlhaus"], tmp_path, now=NOW)
    assert result.status == "ok" and result.entries == 2
    assert fake.calls == ["https://urlhaus-api.abuse.ch/v2/files/exports/abc123/recent.csv"]
    assert feeds.load(tmp_path).lookup("http://mal-ornek.com/a.exe").source == "urlhaus"


def test_a_malformed_key_never_reaches_the_url(tmp_path, net, monkeypatch):
    monkeypatch.setenv(feeds.URLHAUS_KEY_ENV, "abc/../../x")
    fake = net({})
    (result,) = feeds.update(["urlhaus"], tmp_path, now=NOW)
    assert result.status == "failed" and fake.calls == []


def test_error_text_never_contains_the_key(tmp_path, net, monkeypatch):
    monkeypatch.setenv(feeds.URLHAUS_KEY_ENV, "abc123secret")
    net({"https://urlhaus-api.abuse.ch/": OSError(
        "GET https://urlhaus-api.abuse.ch/v2/files/exports/abc123secret/recent.csv failed")})
    (result,) = feeds.update(["urlhaus"], tmp_path, now=NOW)
    assert result.status == "failed"
    assert "abc123secret" not in result.message and "***" in result.message


@pytest.mark.parametrize("answer", [
    OSError("baglanti zaman asimina ugradi"),
    b"<!doctype html><html><body>410 Gone</body></html>",
    b"",
    b"# yalniz yorum\n",
])
def test_a_failed_download_keeps_the_list_on_disk(tmp_path, net, answer):
    net({feeds.OPENPHISH_URL: OPENPHISH_BODY})
    feeds.update(["openphish"], tmp_path, now=NOW)
    before = (tmp_path / "openphish.txt").read_bytes()

    net({feeds.OPENPHISH_URL: answer})
    (result,) = feeds.update(["openphish"], tmp_path, now=NOW + timedelta(days=1))
    assert result.status == "failed" and result.message
    assert (tmp_path / "openphish.txt").read_bytes() == before
    assert not list(tmp_path.glob("*.tmp"))


def test_one_source_failing_does_not_stop_the_others(tmp_path, net):
    net({feeds.OPENPHISH_URL: OSError("yok"),
         feeds.USOM_URL: usom_bytes(["kotu-ornek.com"])})
    status = {r.source: r.status for r in feeds.update(["openphish", "usom"], tmp_path, now=NOW)}
    assert status == {"openphish": "failed", "usom": "ok"}


def test_usom_answer_that_is_not_json(tmp_path, net):
    net({feeds.USOM_URL: b"<!DOCTYPE html><html>SwaggerUI</html>"})
    (result,) = feeds.update(["usom"], tmp_path, now=NOW)
    assert result.status == "failed" and "JSON" in result.message


def test_unknown_source(tmp_path):
    (result,) = feeds.update(["phishtank"], tmp_path, now=NOW)
    assert result.status == "failed"


def test_only_https_is_downloaded(monkeypatch):
    monkeypatch.undo()          # the real helper, which must refuse before any I/O
    with pytest.raises(feeds.FeedError):
        feeds._http_get("http://openphish.com/feed.txt")
    with pytest.raises(feeds.FeedError):
        feeds._http_get("file:///etc/passwd")


def test_every_source_address_is_https():
    for url in (feeds.OPENPHISH_URL, feeds.USOM_URL, feeds.URLHAUS_URL):
        assert url.startswith("https://")


# -- the analysis side never downloads ---------------------------------------

MAIL = (b"From: Destek <destek@ornek-firma-ornek.com>\r\nTo: ali@alici.com\r\n"
        b"Subject: Merhaba\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b'<a href="https://evil-ornek.com/login">buraya</a>\r\n')


def test_build_context_and_analysis_use_the_disk_only(tmp_path):
    # conftest's _http_get raises on any call: reaching this assert at all is
    # the proof that loading the lists and analysing a mail asked nobody.
    (tmp_path / "openphish.txt").write_text("evil-ornek.com/login\n", encoding="utf-8")
    ctx = analyzer.build_context(config=config.DEFAULTS, feeds_dir=tmp_path)
    result = analyzer.analyze(parser.parse_bytes(MAIL), ctx=ctx)
    assert "threat_feed_hit" in {i.id for i in result.indicators}


def test_context_without_lists_and_with_lists_disabled(tmp_path):
    (tmp_path / "openphish.txt").write_text("evil-ornek.com/login\n", encoding="utf-8")
    assert not analyzer.build_context(config=config.DEFAULTS)["feeds"]       # conftest folder
    assert analyzer.build_context(config=config.DEFAULTS, feeds_dir=tmp_path)["feeds"]
    assert not analyzer.build_context(config=config.DEFAULTS, feeds_dir=False)["feeds"]


# -- CLI ---------------------------------------------------------------------

def test_cli_update_reports_each_source(tmp_path, net, monkeypatch, capsys):
    monkeypatch.delenv(feeds.URLHAUS_KEY_ENV, raising=False)
    net({feeds.OPENPHISH_URL: OPENPHISH_BODY, feeds.USOM_URL: usom_bytes(["kotu-ornek.com"])})
    assert cli.main(["feeds", "update", "--feeds-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "openphish  OK       2 kayit" in out
    assert "usom       OK       1 kayit" in out
    assert "urlhaus    ATLANDI" in out and str(tmp_path) in out


def test_cli_update_fails_loudly(tmp_path, net, monkeypatch, capsys):
    monkeypatch.delenv(feeds.URLHAUS_KEY_ENV, raising=False)
    net({feeds.OPENPHISH_URL: OSError("ag yok"), feeds.USOM_URL: usom_bytes(["kotu-ornek.com"])})
    assert cli.main(["feeds", "update", "--feeds-dir", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "openphish  HATA" in out and "ag yok" in out


def test_cli_asking_for_urlhaus_without_a_key_is_a_failure(tmp_path, net, monkeypatch, capsys):
    monkeypatch.delenv(feeds.URLHAUS_KEY_ENV, raising=False)
    net({})
    assert cli.main(["feeds", "update", "--source", "urlhaus",
                     "--feeds-dir", str(tmp_path)]) == 1
    assert "ATLANDI" in capsys.readouterr().out


def test_cli_update_json_and_source_filter(tmp_path, net, capsys):
    fake = net({feeds.OPENPHISH_URL: OPENPHISH_BODY})
    assert cli.main(["feeds", "update", "--source", "openphish", "--json",
                     "--feeds-dir", str(tmp_path)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["dir"] == str(tmp_path)
    assert data["results"] == [{"source": "openphish", "status": "ok",
                                "entries": 2, "message": ""}]
    assert fake.calls == [feeds.OPENPHISH_URL]


def test_cli_update_rejects_a_zero_day_window(tmp_path, capsys):
    assert cli.main(["feeds", "update", "--days", "0", "--feeds-dir", str(tmp_path)]) == 2
    assert "--days" in capsys.readouterr().err


def test_cli_status(tmp_path, capsys):
    assert cli.main(["feeds", "status", "--feeds-dir", str(tmp_path)]) == 0
    assert "Yuklu liste yok" in capsys.readouterr().out

    old = datetime.now(timezone.utc) - timedelta(days=feeds.STALE_DAYS + 5)
    (tmp_path / "openphish.txt").write_text(
        "# source: openphish\n# fetched: " + old.isoformat(timespec="seconds")
        + "\nevil-ornek.com\n", encoding="utf-8")
    assert cli.main(["feeds", "status", "--feeds-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "openphish" in out and "1 kayit" in out and "ESKI" in out

    assert cli.main(["feeds", "status", "--json", "--feeds-dir", str(tmp_path)]) == 0
    (info,) = json.loads(capsys.readouterr().out)["feeds"]
    assert info["source"] == "openphish" and info["entries"] == 1 and info["stale"] is True


def test_cli_analyze_reads_the_lists_it_is_pointed_at(tmp_path, monkeypatch, capsys):
    mail = tmp_path / "m.eml"
    mail.write_bytes(MAIL)
    lists = tmp_path / "lists"
    lists.mkdir()
    (lists / "usom.txt").write_text("# source: usom\nevil-ornek.com\n", encoding="utf-8")

    def ids(*extra):
        assert cli.main(["analyze", str(mail), "--json", *extra]) == 0
        return {i["id"] for i in json.loads(capsys.readouterr().out)["indicators"]}

    assert "threat_feed_hit" not in ids()                          # no lists by default
    assert "threat_feed_hit" in ids("--feeds-dir", str(lists))
    assert "threat_feed_hit" not in ids("--feeds-dir", str(lists), "--no-feeds")
    monkeypatch.setenv("PHISHINGTOOL_FEEDS", str(lists))
    assert "threat_feed_hit" in ids()
    assert "threat_feed_hit" not in ids("--no-feeds")
