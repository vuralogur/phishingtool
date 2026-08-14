"""HTML report: correct content, and no way for the analyzed mail to act."""
import json
import re
from pathlib import Path

from detector import analyzer, cli, html_report, iocs, parser

SAMPLES = Path(__file__).parent / "samples"

# Display name and body carry an injection payload on purpose: the report must
# render it as text, never as markup.
XSS = '<script>alert(1)</script>'
PHISH = (
    'From: "PayPal ' + XSS + '" <alerts@paypa1-secure.tk>\r\n'
    "To: ali@example.com\r\n"
    "Subject: Hesap dogrulama " + XSS + "\r\n"
    "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\r\n"
    "Content-Type: text/html\r\n\r\n"
    '<a href="http://paypa1-secure.tk/login">paypal.com</a>'
    '<img src="http://tracker.tk/pixel.gif">'
)
BENIGN = (SAMPLES / "benign.eml").read_text(encoding="utf-8")


def render(raw=PHISH, with_iocs=False):
    email = parser.parse_text(raw)
    result = analyzer.analyze(email)
    return html_report.to_html(result, source="mail.eml", email=email,
                               iocs=iocs.collect(email) if with_iocs else None)


def test_mail_content_is_escaped_not_rendered():
    page = render()
    assert "<script" not in page          # we emit none, and the mail's is escaped
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_page_loads_nothing_from_the_network():
    page = render()
    assert "<script" not in page
    assert "<link" not in page
    assert "@import" not in page
    assert " src=" not in page            # the mail's tracking pixel included
    for href in re.findall(r'href="([^"]*)"', page):
        assert href.startswith("https://attack.mitre.org/"), href


def test_mail_urls_appear_as_text_but_never_as_links():
    page = render()
    assert "paypa1-secure.tk" in page     # the evidence is still readable
    assert 'href="http://' not in page
    assert 'href="https://paypa1' not in page


def test_verdict_score_and_breakdown_are_shown():
    page = render()
    result = analyzer.analyze(parser.parse_text(PHISH))
    assert result.verdict.upper() in page
    assert str(result.score) + "/" + str(result.max_score) in page
    assert "Skor kırılımı" in page
    assert "Verdict nedeni" in page


def test_indicators_and_attack_techniques_are_listed():
    page = render()
    assert "spf_fail" in page
    assert "MITRE ATT&amp;CK" in page
    assert "https://attack.mitre.org/techniques/T1656/" in page


def test_iocs_are_defanged_in_the_report():
    page = render(with_iocs=True)
    assert "hxxp" in page
    assert "[.]" in page


def test_clean_mail_says_so():
    page = render(BENIGN)
    assert "Gösterge yok" in page
    assert "spf_fail" not in page


def test_mail_identity_is_shown():
    page = render()
    assert "alerts@paypa1-secure.tk" in page
    assert "Hesap dogrulama" in page       # subject, escaped payload and all


def test_report_is_one_self_contained_file():
    page = render()
    assert page.startswith("<!DOCTYPE html>")
    assert "<style>" in page              # CSS embedded, not linked
    assert page.rstrip().endswith("</html>")


# -- CLI ------------------------------------------------------------------


def test_cli_writes_the_file(tmp_path, capsys):
    src = tmp_path / "mail.eml"
    src.write_text(PHISH, encoding="utf-8")
    out = tmp_path / "rapor.html"

    code = cli.main(["analyze", str(src), "--html", str(out)])
    captured = capsys.readouterr()

    assert code == 0
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert "rapor.html" in captured.err


def test_cli_json_stays_valid_json_alongside_html(tmp_path, capsys):
    src = tmp_path / "mail.eml"
    src.write_text(PHISH, encoding="utf-8")

    code = cli.main(["analyze", str(src), "--json", "--iocs",
                     "--html", str(tmp_path / "rapor.html")])
    captured = capsys.readouterr()

    assert code == 0
    assert json.loads(captured.out)["verdict"]      # notice went to stderr
    assert "hxxp" in (tmp_path / "rapor.html").read_text(encoding="utf-8")


def test_cli_reports_an_unwritable_path(tmp_path, capsys):
    src = tmp_path / "mail.eml"
    src.write_text(PHISH, encoding="utf-8")

    code = cli.main(["analyze", str(src),
                     "--html", str(tmp_path / "yok" / "rapor.html")])

    assert code == 2
    assert "HTML yazilamadi" in capsys.readouterr().err
