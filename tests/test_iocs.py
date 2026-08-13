"""IOC export (`--iocs`): extraction, defanging and the CLI wiring."""
import hashlib
import json
from pathlib import Path

from detector import cli, iocs, parser, report

SAMPLES = Path(__file__).parent / "samples"


def _phish():
    return parser.parse_file(SAMPLES / "phish.eml")


def test_collect_urls_hosts_and_ip_literal():
    found = iocs.collect(_phish())
    assert "http://198.51.100.7/login" in found.urls
    assert "http://secure-verify.tk/paypal" in found.urls
    # An IP-literal host is an IP indicator, not a domain.
    assert "198.51.100.7" in found.ips
    assert "198.51.100.7" not in found.domains
    assert "secure-verify.tk" in found.domains


def test_anchor_text_url_is_not_an_ioc():
    # phish.eml shows "https://www.paypal.com/login" as the visible text of a
    # link that points elsewhere. Blocking paypal.com would punish the victim.
    found = iocs.collect(_phish())
    assert "https://www.paypal.com/login" not in found.urls
    assert "paypal.com" not in found.domains
    assert "www.paypal.com" not in found.domains


def test_collect_sender_identities_and_registrable_domain():
    found = iocs.collect(_phish())
    assert "collect@evil-mail.ru" in found.emails
    assert "security@paypal.com.verify-account.tk" in found.emails
    # Both the exact host and the domain the attacker actually registered.
    assert "paypal.com.verify-account.tk" in found.domains
    assert "verify-account.tk" in found.domains


def test_collect_attachment_sha256_matches_payload():
    email = _phish()
    found = iocs.collect(email)
    assert len(found.attachments) == 1
    a = found.attachments[0]
    assert a["filename"] == "fatura.pdf.exe"
    assert a["sha256"] == hashlib.sha256(email.attachments[0].payload).hexdigest()
    assert a["size"] == len(email.attachments[0].payload)


def test_collect_is_deduplicated_and_sorted():
    email = parser.parse_text(
        "From: a@evil.tk\r\nSubject: t\r\nContent-Type: text/html\r\n\r\n"
        '<a href="http://evil.tk/b">b</a><a href="http://evil.tk/a">a</a>'
        '<a href="http://evil.tk/b">again</a>'
    )
    found = iocs.collect(email)
    assert found.urls == ["http://evil.tk/a", "http://evil.tk/b"]
    assert found.domains == ["evil.tk"]


def test_collect_finds_form_action_missed_by_anchor_links():
    email = parser.parse_text(
        "From: a@evil.tk\r\nSubject: t\r\nContent-Type: text/html\r\n\r\n"
        '<form action="http://harvest.example/collect"><input name="pw"></form>'
    )
    found = iocs.collect(email)
    assert "http://harvest.example/collect" in found.urls
    assert "harvest.example" in found.domains


def test_origin_ip_skips_private_ranges():
    email = parser.parse_text(
        "From: a@evil.tk\r\nReceived: from x ([10.0.0.5]) by mx\r\nSubject: t\r\n\r\nhi"
    )
    assert iocs.collect(email).ips == []
    # A routable IP is kept. (Documentation ranges like 203.0.113.0/24 count as
    # private for ipaddress, so they are dropped too - they block nothing.)
    email = parser.parse_text(
        "From: a@evil.tk\r\nReceived: from x ([93.184.216.34]) by mx\r\nSubject: t\r\n\r\nhi"
    )
    assert iocs.collect(email).ips == ["93.184.216.34"]


def test_defang_makes_values_unclickable():
    assert iocs.defang("http://evil.tk/a") == "hxxp://evil[.]tk/a"
    assert iocs.defang("https://evil.tk") == "hxxps://evil[.]tk"
    assert iocs.defang("collect@evil-mail.ru") == "collect[at]evil-mail[.]ru"


def test_empty_message_has_no_iocs():
    found = iocs.collect(parser.parse_text("Subject: bos\r\n\r\nmerhaba"))
    assert found.is_empty()
    assert "  IOC bulunamadı." in report.iocs_lines(found)


def test_report_block_is_defanged():
    block = "\n".join(report.iocs_lines(iocs.collect(_phish())))
    assert "hxxp://198[.]51[.]100[.]7/login" in block
    assert "http://" not in block          # nothing clickable survives
    assert "sha256=" in block


def test_cli_json_carries_raw_iocs(capsys):
    assert cli.main(["analyze", str(SAMPLES / "phish.eml"), "--json", "--iocs"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert "http://198.51.100.7/login" in d["iocs"]["urls"]   # raw, not defanged
    assert d["iocs"]["attachments"][0]["filename"] == "fatura.pdf.exe"


def test_cli_json_omits_iocs_without_the_flag(capsys):
    assert cli.main(["analyze", str(SAMPLES / "phish.eml"), "--json"]) == 0
    assert "iocs" not in json.loads(capsys.readouterr().out)


def test_cli_batch_adds_ioc_columns(capsys):
    assert cli.main(["batch", str(SAMPLES), "--iocs"]) == 0
    out = capsys.readouterr().out.splitlines()
    # IOC columns stay together; the error column is always last.
    assert out[0].endswith("urls,domains,ips,sha256,error")
    assert any("198.51.100.7" in line for line in out[1:])
