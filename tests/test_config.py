"""Scoring overrides: a config file must change the model - loudly or not at all.

Two properties matter more than any single knob. Without a config the tool has
to behave exactly as before (an override mechanism that shifts default scores is
a silent regression), and a config that cannot be honoured has to fail instead
of quietly scoring with the built-in model.
"""
import json

import pytest

from detector import analyzer, cli, config, parser, report, scoring
from detector.indicators import Indicator
from detector.scoring import score

PHISH = (
    "From: PayPal <security@paypa1-alert.tk>\r\n"
    "Reply-To: collect@evil.ru\r\n"
    "To: ali@example.com\r\n"
    "Subject: ACIL: hesabiniz askiya alindi\r\n"
    "Content-Type: text/html\r\n\r\n"
    '<p>Sayin musteri, <a href="http://45.146.164.110/login">hesabinizi</a>'
    " hemen dogrulayin, sifrenizi girin.</p>\r\n"
)


def write(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


def soft_only():
    """Indicators that are all soft, so only the multiplier/threshold matter."""
    return [Indicator("urgency_language", "content", "medium", 8, "e", "x"),
            Indicator("generic_greeting", "content", "low", 6, "e", "x")]


# -- defaults are untouched -------------------------------------------------


def test_no_config_means_the_built_in_model(monkeypatch):
    monkeypatch.delenv(config.ENV, raising=False)
    assert config.resolve() is config.DEFAULTS
    assert config.DEFAULTS.source == "" and config.DEFAULTS.changed == ()
    assert config.DEFAULTS.thresholds == scoring.THRESHOLDS
    assert config.DEFAULTS.soft_ids == frozenset(scoring.SOFT_IDS)


def test_a_config_in_the_working_directory_is_never_auto_discovered(
        tmp_path, monkeypatch):
    """A config.toml lying in the cwd must not change anybody's score."""
    write(tmp_path, "[thresholds]\nhigh = 1\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(config.ENV, raising=False)
    assert config.resolve() is config.DEFAULTS


def test_default_run_scores_exactly_as_the_config_free_model():
    email = parser.parse_text(PHISH)
    ctx = analyzer.build_context()
    with_config = analyzer.analyze(email, ctx=ctx)
    # A ctx without any "config" key at all: the pre-config code path.
    bare = analyzer.analyze(email, ctx={k: v for k, v in ctx.items()
                                        if k != "config"})
    assert with_config.score == bare.score
    assert with_config.verdict == bare.verdict
    assert with_config.breakdown.to_dict()["config"] is None


def test_empty_config_file_is_equivalent_to_the_defaults(tmp_path):
    cfg = config.load(write(tmp_path, "# nothing overridden\n"))
    assert cfg.changed == ()
    assert cfg.thresholds == config.DEFAULTS.thresholds
    assert cfg.soft_ids == config.DEFAULTS.soft_ids
    assert cfg.source  # but it still says where it came from


# -- the four tables ---------------------------------------------------------


def test_weights_replace_the_indicator_weight(tmp_path):
    cfg = config.load(write(tmp_path, "[weights]\nurgency_language = 50\n"))
    r = score(soft_only(), {"spf": "none", "dkim": "none", "dmarc": "none"},
              config=cfg)
    assert r.breakdown.soft_raw == 56          # 50 + 6, not 8 + 6
    assert cfg.changed == ("weights",)


def test_scoring_does_not_mutate_the_caller_indicators(tmp_path):
    cfg = config.load(write(tmp_path, "[weights]\nurgency_language = 50\n"))
    inds = soft_only()
    score(inds, {"spf": "none", "dkim": "none", "dmarc": "none"}, config=cfg)
    assert inds[0].weight == 8                 # the originals are untouched
    assert inds[0].technique == "T1566"        # and keep their ATT&CK tag


def test_thresholds_move_the_verdict(tmp_path):
    hard = [Indicator("dkim_fail", "auth", "high", 12, "e", "x")]
    auth = {"spf": "none", "dkim": "fail", "dmarc": "none"}
    assert score(hard, auth).verdict == "medium"          # default: 12 >= 10
    cfg = config.load(write(tmp_path, "[thresholds]\nmedium = 5\nhigh = 12\n"))
    assert score(hard, auth, config=cfg).verdict == "high"
    assert cfg.changed == ("thresholds",)


def test_soft_multiplier_scales_only_soft_signals(tmp_path):
    cfg = config.load(write(tmp_path, "[soft_multiplier]\nnone = 0.0\n"))
    auth = {"spf": "none", "dkim": "none", "dmarc": "none"}
    r = score(soft_only(), auth, config=cfg)
    assert r.breakdown.multiplier == 0.0 and r.score == 0
    hard = [Indicator("dkim_fail", "auth", "high", 12, "e", "x")]
    assert score(hard, auth, config=cfg).breakdown.hard == 12


def test_soft_ids_remove_promotes_an_indicator_to_hard_evidence(tmp_path):
    inds = [Indicator("urgency_language", "content", "medium", 12, "e", "x")]
    auth = {"spf": "none", "dkim": "none", "dmarc": "none"}
    assert score(inds, auth).verdict == "low"             # soft alone: never up
    cfg = config.load(write(tmp_path, '[soft_ids]\nremove = ["urgency_language"]\n'))
    r = score(inds, auth, config=cfg)
    assert r.verdict == "medium" and r.breakdown.hard == 12
    assert cfg.changed == ("soft_ids",)


def test_soft_ids_add_demotes_an_indicator(tmp_path):
    inds = [Indicator("ip_url", "url", "high", 25, "e", "x")]
    auth = {"spf": "none", "dkim": "none", "dmarc": "none"}
    assert score(inds, auth).verdict == "high"
    cfg = config.load(write(tmp_path, '[soft_ids]\nadd = ["ip_url"]\n'))
    assert score(inds, auth, config=cfg).verdict == "low"


# -- validation: a typo must not be a silent no-op ---------------------------


@pytest.mark.parametrize("text, needle", [
    ("[weight]\nip_url = 5\n", "bilinmeyen bolum"),
    ("[weights]\nip_urls = 5\n", "bilinmeyen gosterge id"),
    ("[weights]\nip_url = 500\n", "araliginda"),
    ("[weights]\nip_url = true\n", "tam sayi"),
    ("[thresholds]\nhigh = 5\nmedium = 40\n", "medium <= high <= critical"),
    ("[thresholds]\nhihg = 5\n", "bilinmeyen anahtar"),
    ("[soft_multiplier]\npass = 3\n", "0..1"),
    ("[soft_multiplier]\npas = 0.5\n", "bilinmeyen anahtar"),
    ('[soft_ids]\nadd = ["nope"]\n', "bilinmeyen gosterge id"),
    ('[soft_ids]\nadd = ["ip_url"]\nremove = ["ip_url"]\n', "hem add hem remove"),
    ('[soft_ids]\nkeep = ["ip_url"]\n', "bilinmeyen anahtar"),
    ("[weights]\nip_url =\n", "bozuk"),
])
def test_bad_config_raises_with_the_reason(tmp_path, text, needle):
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, text))
    assert needle in str(exc.value)


def test_a_bom_written_by_a_windows_editor_is_tolerated(tmp_path):
    """Notepad/PowerShell "UTF-8" means UTF-8 with a BOM; TOML has no BOM."""
    p = tmp_path / "bom.toml"
    p.write_bytes(b"\xef\xbb\xbf[thresholds]\nhigh = 30\n")
    assert config.load(p).thresholds["high"] == 30


def test_missing_file_is_an_error_not_a_fallback(tmp_path):
    with pytest.raises(config.ConfigError) as exc:
        config.load(tmp_path / "yok.toml")
    assert "yok.toml" in str(exc.value)


def test_every_known_id_is_accepted_as_a_weight_key():
    """The weight table's vocabulary is exactly the indicator registry."""
    raw = {"weights": {i: 1 for i in sorted(config.KNOWN_IDS)}}
    assert len(config.from_dict(raw).weights) == len(config.KNOWN_IDS)
    assert config.KNOWN_IDS >= frozenset(scoring.SOFT_IDS)


def test_the_shipped_example_file_parses():
    cfg = config.load("config.example.toml")
    assert cfg.changed == ()          # every line is commented out on purpose


# -- precedence, plumbing, visibility ---------------------------------------


def test_argument_beats_environment(tmp_path, monkeypatch):
    env = tmp_path / "env.toml"
    env.write_text("[thresholds]\nhigh = 40\n", encoding="utf-8")
    arg = tmp_path / "arg.toml"
    arg.write_text("[thresholds]\nhigh = 30\n", encoding="utf-8")
    monkeypatch.setenv(config.ENV, str(env))
    assert config.resolve().thresholds["high"] == 40      # env when no argument
    assert config.resolve(arg).thresholds["high"] == 30   # argument wins


def test_an_explicit_config_object_ignores_the_environment(tmp_path, monkeypatch):
    """How a caller (e.g. the GUI, after a bad env file) pins a known policy."""
    env = tmp_path / "env.toml"
    env.write_text("[thresholds]\nhigh = 40\n", encoding="utf-8")
    monkeypatch.setenv(config.ENV, str(env))
    assert config.resolve(config.DEFAULTS) is config.DEFAULTS
    ctx = analyzer.build_context(config=config.DEFAULTS)
    assert ctx["config"].thresholds["high"] == 22


def test_build_context_carries_the_config_into_analysis(tmp_path):
    ctx = analyzer.build_context(config=write(
        tmp_path, "[thresholds]\nmedium = 1\nhigh = 1\ncritical = 1\n"))
    r = analyzer.analyze(parser.parse_text(PHISH), ctx=ctx)
    assert r.verdict == "critical" and r.breakdown.reason == "hard_critical"


def test_the_report_names_the_config_that_produced_the_score(tmp_path):
    ctx = analyzer.build_context(config=write(
        tmp_path, "[thresholds]\nmedium = 1\nhigh = 1\ncritical = 1\n"))
    r = analyzer.analyze(parser.parse_text(PHISH), ctx=ctx)
    lines = report.breakdown_lines(r)
    assert len(lines) == 3
    assert "Ayar dosyası:" in lines[2] and "eşikler" in lines[2]
    d = json.loads(report.to_json(r))["breakdown"]
    assert d["config"]["changed"] == ["thresholds"]


def test_cli_passes_config_and_rejects_a_broken_one(tmp_path, capsys):
    mail = tmp_path / "mail.eml"
    mail.write_text(PHISH, encoding="utf-8")
    good = write(tmp_path, "[thresholds]\nmedium = 1\nhigh = 1\ncritical = 1\n")
    assert cli.main(["analyze", str(mail), "--config", str(good), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "critical"

    bad = tmp_path / "bad.toml"
    bad.write_text("[weights]\nip_urls = 5\n", encoding="utf-8")
    assert cli.main(["analyze", str(mail), "--config", str(bad)]) == 2
    assert "bilinmeyen gosterge id" in capsys.readouterr().err


def test_bench_splits_hard_and_soft_the_way_the_config_says(tmp_path):
    from detector import bench
    (tmp_path / "a.eml").write_text(PHISH, encoding="utf-8")
    (tmp_path / "labels.csv").write_text("file,label\na.eml,phish\n",
                                         encoding="utf-8")
    cfg = write(tmp_path, '[soft_ids]\nadd = ["ip_url"]\n')
    result = bench.run(tmp_path, ctx=analyzer.build_context(config=cfg))
    assert "ip_url" not in result.cases[0].hard_ids
