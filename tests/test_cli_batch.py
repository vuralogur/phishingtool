"""batch error reporting: an unreadable mail must say WHY, not vanish.

A silent "error" row is a false negative nobody can see - the mail left the scan
and the operator has no idea which rule, parser or attachment blew up.
"""
import json
from pathlib import Path

import pytest

from detector import analyzer, cli

SAMPLES = Path(__file__).parent / "samples"


@pytest.fixture
def boom(monkeypatch):
    """Make every analysis fail, the way a corrupt sample would."""
    def explode(email, online=False, ctx=None):
        raise ValueError("bozuk ornek")
    monkeypatch.setattr(analyzer, "analyze", explode)


def test_clean_run_exits_zero_with_an_empty_error_column(capsys):
    assert cli.main(["batch", str(SAMPLES)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].endswith(",error")
    assert all(line.endswith(",") for line in out[1:])   # empty last field


def test_failure_reason_lands_in_csv_and_stderr(boom, capsys):
    assert cli.main(["batch", str(SAMPLES)]) == 1        # not a successful run
    cap = capsys.readouterr()
    rows = cap.out.splitlines()
    assert rows[0].endswith(",error")
    assert all("ValueError: bozuk ornek" in line for line in rows[1:])
    assert "HATA: phish.eml: ValueError: bozuk ornek" in cap.err
    assert "Traceback" not in cap.err                    # only with --verbose


def test_verbose_adds_the_traceback(boom, capsys):
    assert cli.main(["batch", str(SAMPLES), "--verbose"]) == 1
    assert "Traceback" in capsys.readouterr().err


def test_json_error_row_carries_the_message(boom, capsys):
    assert cli.main(["batch", str(SAMPLES), "--json"]) == 1
    rows = json.loads(capsys.readouterr().out)
    assert rows and all(r["error"].startswith("ValueError") for r in rows)
    assert all("verdict" not in r for r in rows)


def test_error_message_survives_an_exception_with_no_text(monkeypatch, capsys):
    monkeypatch.setattr(analyzer, "analyze",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    assert cli.main(["batch", str(SAMPLES), "--json"]) == 1
    rows = json.loads(capsys.readouterr().out)
    assert all(r["error"] == "RuntimeError" for r in rows)
