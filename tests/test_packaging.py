"""Packaging: bundled dictionaries, data-dir overrides, project metadata."""
import tomllib
from pathlib import Path

from detector import analyzer

ROOT = Path(__file__).resolve().parent.parent
DATA_FILES = ("brands.txt", "suspicious_tlds.txt", "urgency_keywords.txt",
              "trusted_domains.txt")


def test_dictionaries_ship_inside_the_package():
    # They must live next to the code, not at the repo root: an installed
    # console script has no repo root to look at.
    bundled = Path(analyzer.__file__).resolve().parent / "data"
    for name in DATA_FILES:
        assert (bundled / name).is_file(), name
    assert analyzer.resolve_data_dir() == bundled


def test_build_context_loads_the_bundled_dictionaries():
    ctx = analyzer.build_context()
    assert ctx["brands"] and ctx["suspicious_tlds"] and ctx["urgency"]


def test_data_dir_override_order(tmp_path, monkeypatch):
    env_dir = tmp_path / "env"
    arg_dir = tmp_path / "arg"
    monkeypatch.setenv("PHISHINGTOOL_DATA", str(env_dir))
    assert analyzer.resolve_data_dir() == env_dir            # env beats bundled
    assert analyzer.resolve_data_dir(arg_dir) == arg_dir     # argument beats env
    monkeypatch.delenv("PHISHINGTOOL_DATA")
    assert analyzer.resolve_data_dir() == Path(analyzer.__file__).resolve().parent / "data"


def test_custom_data_dir_is_actually_read(tmp_path):
    (tmp_path / "brands.txt").write_text("acme,acme.example\n", encoding="utf-8")
    ctx = analyzer.build_context(tmp_path)
    assert ctx["brands"] == {"acme": {"acme.example"}}
    assert ctx["suspicious_tlds"] == set()   # missing files degrade to empty


def test_pyproject_declares_console_script_and_package_data():
    with open(ROOT / "pyproject.toml", "rb") as fh:
        cfg = tomllib.load(fh)
    assert cfg["project"]["scripts"]["phishingtool"] == "detector.cli:main"
    assert "detector" in cfg["tool"]["setuptools"]["packages"]
    assert "detector.checks" in cfg["tool"]["setuptools"]["packages"]
    assert cfg["tool"]["setuptools"]["package-data"]["detector"] == ["data/*.txt"]
    # The core must stay dependency-free; extras carry everything optional.
    assert cfg["project"]["dependencies"] == []
    assert set(cfg["project"]["optional-dependencies"]) >= {"cli", "online", "deep", "dev"}


def test_license_is_declared_and_shipped():
    assert cfg_license() == "MIT"
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License")
    assert "Copyright (c) 2026 vuralogr" in text


def cfg_license() -> str:
    with open(ROOT / "pyproject.toml", "rb") as fh:
        cfg = tomllib.load(fh)
    assert cfg["project"]["license-files"] == ["LICENSE"]
    return cfg["project"]["license"]
