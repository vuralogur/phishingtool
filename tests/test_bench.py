"""Benchmark harness tests: label loading, metric math, and a real corpus run."""
import json
import shutil
from pathlib import Path

import pytest

from detector import bench, report

SAMPLES = Path(__file__).parent / "samples"


def _corpus(tmp_path, with_csv=True):
    """Build a 3-file corpus: 2 phishing samples + 1 benign one."""
    shutil.copy(SAMPLES / "benign.eml", tmp_path / "iyi.eml")
    shutil.copy(SAMPLES / "phish.eml", tmp_path / "kotu1.eml")
    shutil.copy(SAMPLES / "phish_tier2.eml", tmp_path / "kotu2.eml")
    if with_csv:
        (tmp_path / "labels.csv").write_text(
            "file,label\niyi.eml,ham\nkotu1.eml,phish\nkotu2.eml,phish\n",
            encoding="utf-8")
    return tmp_path


def _case(label, verdict, score=0, file="x.eml"):
    return bench.Case(file=file, label=label, verdict=verdict, score=score)


# ---------------------------------------------------------------------------
# Metric math - independent of the analyzer
# ---------------------------------------------------------------------------

def test_metrics_math():
    m = bench.Metrics(tp=8, fp=2, fn=4, tn=6)
    assert m.total == 20
    assert m.precision == pytest.approx(0.8)     # 8 / (8+2)
    assert m.recall == pytest.approx(8 / 12)
    assert m.f1 == pytest.approx(2 * 0.8 * (8 / 12) / (0.8 + 8 / 12))
    assert m.accuracy == pytest.approx(14 / 20)
    assert m.false_positive_rate == pytest.approx(2 / 8)


def test_metrics_no_division_by_zero():
    m = bench.Metrics()
    assert (m.precision, m.recall, m.f1, m.accuracy, m.false_positive_rate) == \
        (0.0, 0.0, 0.0, 0.0, 0.0)


def test_case_outcome_by_threshold():
    c = _case("phish", "medium")
    assert c.outcome("medium") == "TP"
    assert c.outcome("high") == "FN"      # stricter cut-off misses it
    assert _case("ham", "high").outcome("medium") == "FP"
    assert _case("ham", "low").outcome("medium") == "TN"


def test_sweep_reports_every_threshold():
    r = bench.BenchResult(threshold="medium", cases=[
        _case("phish", "critical"), _case("phish", "medium"), _case("ham", "high"),
    ])
    sweep = dict(r.sweep())
    assert set(sweep) == set(bench.THRESHOLDS)
    assert sweep["medium"].tp == 2 and sweep["medium"].fp == 1
    assert sweep["critical"].tp == 1 and sweep["critical"].fp == 0  # ham no longer flagged
    assert sweep["critical"].fn == 1


def test_errored_case_excluded_from_metrics():
    c = bench.Case(file="bozuk.eml", label="phish", error="ValueError: x")
    r = bench.BenchResult(threshold="medium", cases=[c, _case("phish", "high")])
    assert r.metrics().total == 1
    assert [x.file for x in r.errors] == ["bozuk.eml"]


# ---------------------------------------------------------------------------
# Label discovery
# ---------------------------------------------------------------------------

def test_normalize_label_aliases():
    for raw in ("phish", "PHISHING", " Malicious ", "1", "spam"):
        assert bench.normalize_label(raw) == "phish"
    for raw in ("ham", "Benign", "legit", "0", "clean"):
        assert bench.normalize_label(raw) == "ham"
    assert bench.normalize_label("belkide") == ""


def test_load_labels_csv_skips_header_and_comments(tmp_path):
    p = tmp_path / "labels.csv"
    p.write_text("file,label\n# yorum\n\na.eml,phish\nb.eml,ham\n", encoding="utf-8")
    assert bench.load_labels_csv(p) == {"a.eml": "phish", "b.eml": "ham"}


def test_load_labels_csv_without_header(tmp_path):
    p = tmp_path / "l.csv"
    p.write_text("a.eml,1\nb.eml,0\n", encoding="utf-8")
    assert bench.load_labels_csv(p) == {"a.eml": "phish", "b.eml": "ham"}


def test_load_labels_csv_all_bad_raises(tmp_path):
    p = tmp_path / "l.csv"
    p.write_text("a.eml,belkide\nb.eml,hmm\n", encoding="utf-8")
    with pytest.raises(bench.BenchError):
        bench.load_labels_csv(p)


def test_labels_from_folders(tmp_path):
    (tmp_path / "phish").mkdir()
    (tmp_path / "ham").mkdir()
    (tmp_path / "notlar").mkdir()          # unrelated folder must be ignored
    shutil.copy(SAMPLES / "phish.eml", tmp_path / "phish" / "a.eml")
    shutil.copy(SAMPLES / "benign.eml", tmp_path / "ham" / "b.eml")
    shutil.copy(SAMPLES / "benign.eml", tmp_path / "notlar" / "c.eml")
    assert bench.labels_from_folders(tmp_path) == {
        "phish/a.eml": "phish", "ham/b.eml": "ham"}


def test_discover_labels_needs_something(tmp_path):
    with pytest.raises(bench.BenchError):
        bench.discover_labels(tmp_path)


# ---------------------------------------------------------------------------
# End-to-end runs
# ---------------------------------------------------------------------------

def test_run_on_labelled_corpus_is_perfect(tmp_path):
    r = bench.run(_corpus(tmp_path))
    m = r.metrics()
    assert (m.tp, m.fp, m.fn, m.tn) == (2, 0, 0, 1)
    assert m.precision == 1.0 and m.recall == 1.0 and m.f1 == 1.0
    assert r.failures("FP") == [] and r.failures("FN") == []


def test_run_records_hard_ids_for_inspection(tmp_path):
    r = bench.run(_corpus(tmp_path))
    kotu = next(c for c in r.cases if c.file == "kotu1.eml")
    assert "spf_fail" in kotu.hard_ids
    assert "urgency_language" not in kotu.hard_ids   # soft signals excluded


def test_run_with_folder_layout(tmp_path):
    (tmp_path / "phish").mkdir()
    (tmp_path / "ham").mkdir()
    shutil.copy(SAMPLES / "phish.eml", tmp_path / "phish" / "a.eml")
    shutil.copy(SAMPLES / "benign.eml", tmp_path / "ham" / "b.eml")
    m = bench.run(tmp_path).metrics()
    assert (m.tp, m.tn, m.fp, m.fn) == (1, 1, 0, 0)


def test_run_reports_missing_and_unlabeled(tmp_path):
    _corpus(tmp_path, with_csv=False)
    (tmp_path / "labels.csv").write_text("yok.eml,phish\niyi.eml,ham\n", encoding="utf-8")
    r = bench.run(tmp_path)
    assert r.missing == ["yok.eml"]
    assert set(r.unlabeled) == {"kotu1.eml", "kotu2.eml"}
    assert len(r.cases) == 1          # only the file that exists was analyzed


def test_run_rejects_bad_threshold_and_dir(tmp_path):
    with pytest.raises(bench.BenchError):
        bench.run(_corpus(tmp_path), threshold="asiri")
    with pytest.raises(bench.BenchError):
        bench.run(tmp_path / "olmayan-klasor")


def test_run_offline_by_default_is_deterministic(tmp_path):
    corpus = _corpus(tmp_path)
    a = bench.run(corpus).to_dict()["metrics"]
    b = bench.run(corpus).to_dict()["metrics"]
    assert a == b


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def test_bench_json_shape(tmp_path):
    d = json.loads(report.bench_to_json(bench.run(_corpus(tmp_path)), source="korpus"))
    assert d["source"] == "korpus"
    assert d["corpus_size"] == 3
    assert d["metrics"]["precision"] == 1.0
    assert set(d["sweep"]) == set(bench.THRESHOLDS)
    assert d["false_positives"] == [] and d["false_negatives"] == []


def test_bench_text_render(tmp_path, capsys):
    report.print_bench(bench.run(_corpus(tmp_path)), source="korpus")
    out = capsys.readouterr().out
    assert "precision" in out and "recall" in out
    assert "TP=2" in out and "TN=1" in out
    assert "Esik taramasi" in out


def test_bench_text_lists_failures():
    r = bench.BenchResult(threshold="medium", cases=[
        bench.Case(file="mesru.eml", label="ham", verdict="high", score=40,
                   hard_ids=["brand_impersonation"]),
        bench.Case(file="kacan.eml", label="phish", verdict="low", score=5),
    ])
    out = report._bench_plain(r)
    assert "mesru.eml" in out and "brand_impersonation" in out
    assert "kacan.eml" in out and "(sert iz yok)" in out
