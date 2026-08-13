"""MITRE ATT&CK tagging: the mapping, the auto-stamp, and where it surfaces."""
import json
import re
from pathlib import Path

from detector import analyzer, mitre, report
from detector.indicators import Indicator

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = Path(__file__).parent / "samples"

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_ID_LITERAL = re.compile(r'Indicator\(\s*"([a-z0-9_]+)"')
# headers.py builds these at runtime ("spf_" + the SPF result), so the source
# scan below only ever sees the prefix.
_RUNTIME_BUILT = ("spf_fail", "spf_softfail")


def _source_indicator_ids() -> set:
    ids = set()
    for path in (ROOT / "detector").rglob("*.py"):
        ids |= set(_ID_LITERAL.findall(path.read_text(encoding="utf-8")))
    return ids


def test_every_technique_id_is_well_formed_and_named():
    for ind_id, tid in mitre.TECHNIQUES.items():
        assert _TECHNIQUE_ID.match(tid), (ind_id, tid)
        assert mitre.NAMES.get(tid), tid


def test_no_indicator_is_silently_unmapped():
    """Drift guard: a new check must map a technique or opt out explicitly."""
    found = _source_indicator_ids()
    assert len(found) > 40, "regex no longer matches the Indicator() calls"
    known = set(mitre.TECHNIQUES) | set(mitre.NO_TECHNIQUE)
    # A trailing "_" means the id is completed at runtime (see _RUNTIME_BUILT).
    missing = {i for i in found if not i.endswith("_") and i not in known}
    assert not missing, "eslenmemis gosterge: " + ", ".join(sorted(missing))


def test_runtime_built_ids_are_mapped():
    for ind_id in _RUNTIME_BUILT:
        assert ind_id in mitre.TECHNIQUES


def test_indicator_is_tagged_on_construction():
    i = Indicator("anchor_href_mismatch", "url", "high", 20, "e", "x")
    assert i.technique == "T1566.002"
    assert i.technique_name == "Phishing: Spearphishing Link"


def test_explicitly_unmapped_indicator_stays_empty():
    i = Indicator("vt_flagged", "reputation", "critical", 25, "e", "x")
    assert (i.technique, i.technique_name) == ("", "")


def test_caller_supplied_technique_wins_and_gets_its_name():
    i = Indicator("brand_new_check", "url", "low", 1, "e", "x", technique="T1566")
    assert (i.technique, i.technique_name) == ("T1566", "Phishing")


def test_url_points_at_the_sub_technique_page():
    assert mitre.url("T1566.002") == "https://attack.mitre.org/techniques/T1566/002/"
    assert mitre.url("T1656") == "https://attack.mitre.org/techniques/T1656/"
    assert mitre.url("") == ""


def test_summary_groups_indicators_by_technique():
    rows = mitre.summary([
        Indicator("ip_url", "url", "high", 14, "e", "x"),
        Indicator("url_shortener", "url", "medium", 8, "e", "x"),
        Indicator("dmarc_fail", "auth", "high", 15, "e", "x"),
        Indicator("vt_flagged", "reputation", "critical", 25, "e", "x"),
    ])
    by_id = {r["id"]: r for r in rows}
    assert by_id["T1566.002"]["indicators"] == ["ip_url", "url_shortener"]
    assert by_id["T1656"]["name"] == "Impersonation"
    assert [r["id"] for r in rows] == sorted(by_id)   # stable across runs
    assert len(rows) == 2                             # unmapped adds no row


def test_phish_sample_reports_expected_techniques():
    r = analyzer.analyze_file(SAMPLES / "phish.eml")
    ids = {t["id"] for t in mitre.summary(r.indicators)}
    # spoofed sender, malicious link, malicious attachment, disguised filename
    assert {"T1656", "T1566.002", "T1566.001", "T1036.007"} <= ids


def test_techniques_reach_report_and_json():
    r = analyzer.analyze_file(SAMPLES / "phish.eml")
    text = report._plain(r, "phish.eml")
    assert "MITRE ATT&CK teknikleri" in text
    assert "T1566.002" in text
    assert report.technique_summary_line(r).startswith("ATT&CK: ")
    d = json.loads(report.to_json(r))
    assert any(t["id"] == "T1566.002" for t in d["techniques"])
    assert all(i["technique"] or i["id"] in mitre.NO_TECHNIQUE
               for i in d["indicators"])


def test_tagging_is_metadata_only_and_does_not_move_the_score():
    assert analyzer.analyze_file(SAMPLES / "benign.eml").score == 0
    assert analyzer.analyze_file(SAMPLES / "phish.eml").verdict in ("high", "critical")
