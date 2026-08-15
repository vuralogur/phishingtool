"""Received chain: the route the mail claims to have taken, read correctly.

The chain is metadata - it explains a verdict, it must never change one - so
these tests pin the parsing, the flags and the fact that reading a hop resolves
nothing over the network.
"""
import json
import socket

import pytest

from detector import cli, html_report, parser, received, report

# Newest first, exactly as an MTA stacks them. Hop 1 (the last line) is where
# the mail entered: an evil.tk sender whose reverse name says bad.net.
CHAIN = (
    "Received: from mx.example.com (mx.example.com [93.184.216.34])"
    " by imap.example.com with ESMTPS id C3;"
    " Fri, 14 Aug 2026 10:00:12 +0300\r\n"
    "Received: from mail.evil.tk (host9.bad.net [45.146.164.110])"
    " by mx.example.com with ESMTP id A1 for <ali@example.com>;"
    " Fri, 14 Aug 2026 09:59:58 +0300\r\n"
    "From: alerts@evil.tk\r\n"
    "Subject: test\r\n\r\nhi\r\n"
)


def hops(raw=CHAIN):
    return received.parse(parser.parse_text(raw))


def one(line):
    """A single Received line, wrapped in the smallest possible mail."""
    return hops("Received: " + line + "\r\nFrom: a@x.com\r\nSubject: t\r\n\r\nhi")[0]


# -- parsing ---------------------------------------------------------------


def test_hops_come_back_in_travel_order():
    chain = hops()
    assert [h.index for h in chain] == [1, 2]
    assert chain[0].from_host == "mail.evil.tk"      # oldest = where it entered
    assert chain[1].by_host == "imap.example.com"    # newest = our own server


def test_announced_name_reverse_name_and_ip_are_separated():
    hop = hops()[0]
    assert hop.from_host == "mail.evil.tk"
    assert hop.from_rdns == "host9.bad.net"
    assert hop.from_ip == "45.146.164.110"
    assert hop.by_host == "mx.example.com"
    assert hop.for_addr == "ali@example.com"


def test_protocol_and_tls_are_read_per_hop():
    first, second = hops()
    assert (first.protocol, first.tls) == ("ESMTP", False)
    assert (second.protocol, second.tls) == ("ESMTPS", True)


def test_delay_is_measured_against_the_previous_hop():
    first, second = hops()
    assert first.delay is None      # nothing to compare the first hop against
    assert second.delay == 14


def test_exim_style_helo_is_the_announced_name_not_a_reverse_lookup():
    hop = one("from unknown ([45.146.164.110] helo=mail.evil.tk)"
              " by mx.example.com with ESMTP")
    assert hop.from_host == "mail.evil.tk"
    assert hop.from_ip == "45.146.164.110"
    assert hop.from_rdns == ""               # nothing here is a reverse name
    assert "rdns_mismatch" not in hop.flags  # so nothing to mismatch against


def test_a_line_we_cannot_read_is_still_reported():
    hop = one("mangled ;; not a received line at all")
    assert "unparsed" in hop.flags
    assert "mangled" in hop.raw             # kept verbatim for the analyst


def test_a_missing_timestamp_is_not_an_error():
    hop = one("from mail.evil.tk ([45.146.164.110]) by mx.example.com")
    assert hop.time is None
    assert hop.delay is None


def test_a_mail_without_received_headers_has_no_chain():
    assert hops("From: a@x.com\r\nSubject: t\r\n\r\nhi") == []


# -- flags -----------------------------------------------------------------


def test_reverse_name_mismatch_is_flagged_only_when_it_mismatches():
    first, second = hops()
    assert "rdns_mismatch" in first.flags       # evil.tk announced, bad.net real
    assert "rdns_mismatch" not in second.flags  # mx.example.com both ways


def test_private_origin_is_flagged():
    hop = one("from internal ([10.0.0.5]) by mx.example.com with ESMTP")
    assert "private_ip" in hop.flags
    assert "no_tls" not in hop.flags    # a hop inside one box is not the wire


def test_plaintext_internet_hop_is_flagged():
    first, second = hops()
    assert "no_tls" in first.flags
    assert "no_tls" not in second.flags


def test_long_pause_and_backwards_clock_are_flagged():
    slow = hops(
        "Received: from b.example.com ([93.184.216.34]) by c.example.com"
        " with ESMTPS; Fri, 14 Aug 2026 10:30:00 +0300\r\n"
        "Received: from a.example.com ([93.184.216.34]) by b.example.com"
        " with ESMTPS; Fri, 14 Aug 2026 10:00:00 +0300\r\n"
        "From: a@x.com\r\nSubject: t\r\n\r\nhi")
    assert slow[1].delay == 1800 and "big_delay" in slow[1].flags

    backwards = hops(
        "Received: from b.example.com ([93.184.216.34]) by c.example.com"
        " with ESMTPS; Fri, 14 Aug 2026 09:59:00 +0300\r\n"
        "Received: from a.example.com ([93.184.216.34]) by b.example.com"
        " with ESMTPS; Fri, 14 Aug 2026 10:00:00 +0300\r\n"
        "From: a@x.com\r\nSubject: t\r\n\r\nhi")
    assert "clock_skew" in backwards[1].flags


def test_summary_reduces_the_chain_to_one_glance():
    s = received.summary(hops())
    assert s["count"] == 2
    assert s["origin_ip"] == "45.146.164.110"
    assert s["span"] == 14
    assert "rdns_mismatch" in s["flags"]


# -- boundaries ------------------------------------------------------------


def test_parsing_a_hop_never_resolves_anything(monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("Received parsing must not touch the network")

    for name in ("gethostbyaddr", "gethostbyname", "getaddrinfo", "create_connection"):
        monkeypatch.setattr(socket, name, forbidden)
    assert hops()[0].from_rdns == "host9.bad.net"   # taken from the header text


def test_the_chain_does_not_move_the_score():
    from detector import analyzer

    email = parser.parse_text(CHAIN)
    before = analyzer.analyze(email)
    received.parse(email)
    after = analyzer.analyze(email)
    assert (before.score, before.verdict) == (after.score, after.verdict)


# -- reporting -------------------------------------------------------------


def test_text_block_shows_every_hop_and_the_trust_caveat():
    text = "\n".join(report.received_lines(hops()))
    assert "mail.evil.tk" in text and "host9.bad.net" in text
    assert "45.146.164.110" in text
    assert "+14 sn" in text
    assert report.HOP_TRUST_NOTE in text


def test_asking_for_a_chain_that_does_not_exist_says_so():
    assert report.received_lines(None) == []          # nobody asked
    assert "Received" in report.received_lines([])[0]  # asked, mail has none


def test_summary_line_fits_one_row():
    line = report.received_summary_line(hops())
    assert line.startswith("Received: 2 hop")
    assert "45.146.164.110" in line
    assert report.received_summary_line([]) == ""


def test_json_carries_the_chain_only_when_asked():
    from detector import analyzer

    email = parser.parse_text(CHAIN)
    result = analyzer.analyze(email)
    assert "received" not in json.loads(report.to_json(result))
    payload = json.loads(report.to_json(result, hops=received.parse(email)))
    assert payload["received"][0]["from_ip"] == "45.146.164.110"
    assert payload["received"][0]["time"].startswith("2026-08-14T09:59:58")


def test_html_shows_the_route_without_making_it_clickable():
    from detector import analyzer

    email = parser.parse_text(CHAIN)
    page = html_report.to_html(analyzer.analyze(email), source="mail.eml",
                               email=email, hops=received.parse(email))
    assert "Received zinciri" in page
    assert "host9.bad.net" in page
    assert 'href="http://' not in page


def test_cli_hops_flag(tmp_path, capsys):
    src = tmp_path / "mail.eml"
    # Bytes, not write_text: on Windows the text path would turn every CRLF in
    # the header block into CR CR LF and split the chain we are testing.
    src.write_bytes(CHAIN.encode("utf-8"))

    assert cli.main(["analyze", str(src), "--hops", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [h["index"] for h in payload["received"]] == [1, 2]

    assert cli.main(["analyze", str(src)]) == 0
    assert "Received" not in capsys.readouterr().out   # opt-in only


@pytest.mark.parametrize("line, expected", [
    ("from mail.x ([93.184.216.34]) by mx.example.com", "93.184.216.34"),
    ("from mail.x (mail.x [IPv6:2001:db8::1]) by mx.example.com", "2001:db8::1"),
    ("from mail.x (mail.x [93.184.216.34:25]) by mx.example.com", "93.184.216.34"),
    ("by mx.example.com with local", ""),
])
def test_ip_shapes_seen_in_the_wild(line, expected):
    assert one(line).from_ip == expected
