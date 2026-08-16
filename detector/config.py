"""Optional TOML overrides for the scoring model (weights, thresholds, soft set).

``scoring.py`` ships one opinionated model, but "how many points is a macro
worth" is a local policy question - a bank's SOC and a small business tolerate
very different false-positive rates. This module lets that policy live in a file
instead of a fork.

Three rules keep it honest:

* **Opt-in.** Without ``--config`` (or ``PHISHINGTOOL_CONFIG``) nothing is read -
  no ``config.toml`` is auto-discovered from the working directory, because a
  file picked up implicitly would silently change everyone's scores.
* **Loud.** An unknown table, an unknown indicator id, a non-monotonic threshold
  or an out-of-range multiplier raises ``ConfigError``. A typo that quietly does
  nothing is the worst possible outcome for a tuning file.
* **Visible.** A loaded config is named in the report's score breakdown, so a
  number nobody can reproduce with the defaults still explains itself.

Schema - every table and every key is optional, anything omitted keeps its
built-in value::

    [weights]              # indicator id -> points (0..100)
    urgency_language = 3

    [thresholds]           # hard-subtotal cut-offs; medium <= high <= critical
    medium = 10
    high = 22
    critical = 45
    soft_pileup = 30       # hard > 0 and total >= this -> medium
    allowlist = 22         # trusted sender with hard < this -> low

    [soft_multiplier]      # authentication level -> soft-signal scale (0..1)
    pass = 0.3
    partial = 0.6
    fail = 1.0
    none = 1.0

    [soft_ids]             # move indicators between the soft and hard sets
    add = ["qr_suspicious_url"]
    remove = ["urgency_language"]
"""
from __future__ import annotations
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import mitre
from . import scoring

ENV = "PHISHINGTOOL_CONFIG"

# Every indicator this tool can raise. detector/mitre.py is the registry - its
# drift test fails when a new Indicator id is listed nowhere - so an id missing
# from this set is a typo, not a check we have simply not heard of yet.
KNOWN_IDS = frozenset(mitre.TECHNIQUES) | mitre.NO_TECHNIQUE

_TABLES = ("weights", "thresholds", "soft_multiplier", "soft_ids")
_SOFT_KEYS = ("add", "remove")
_MAX_WEIGHT = 100


class ConfigError(Exception):
    """The config file is missing, malformed, or asks for something impossible."""


@dataclass(frozen=True)
class Config:
    """A resolved scoring policy: the defaults with any overrides folded in.

    ``source`` is the file it came from ("" = built-in defaults, nothing read)
    and ``changed`` names the tables that actually differ from the defaults, so
    the report can say what was overridden without diffing anything itself.
    """
    weights: dict          # indicator id -> weight, replaces the check's own
    thresholds: dict       # medium / high / critical / soft_pileup / allowlist
    soft_mult: dict        # auth level -> soft multiplier
    soft_ids: frozenset    # which indicators count as soft
    source: str = ""
    changed: tuple = ()

    def to_dict(self) -> dict:
        return {"source": self.source, "changed": list(self.changed)}


DEFAULTS = Config(
    weights={},
    thresholds=dict(scoring.THRESHOLDS),
    soft_mult=dict(scoring.SOFT_MULT),
    soft_ids=frozenset(scoring.SOFT_IDS),
)


def resolve(path=None) -> Config:
    """Which policy applies: argument > PHISHINGTOOL_CONFIG > built-in defaults.

    An already-built ``Config`` passes through unchanged, which is how a caller
    asks for a specific policy (``DEFAULTS`` included) without the environment
    getting a vote.
    """
    if isinstance(path, Config):
        return path
    if path:
        return load(path)
    env = os.environ.get(ENV, "").strip()
    return load(env) if env else DEFAULTS


def load(path) -> Config:
    """Read and validate a TOML file. Raises ``ConfigError`` on any problem."""
    p = Path(path)
    try:
        # utf-8-sig, not tomllib.load(fh): Notepad and PowerShell put a BOM in
        # front of "UTF-8" files, and a byte-order mark is not a TOML statement.
        text = p.read_bytes().decode("utf-8-sig")
    except FileNotFoundError:
        raise ConfigError("ayar dosyasi yok: " + str(p)) from None
    except UnicodeDecodeError:
        raise ConfigError("ayar dosyasi UTF-8 degil: " + str(p)) from None
    except OSError as exc:
        raise ConfigError("ayar dosyasi okunamadi (" + str(p) + "): " +
                          str(exc)) from None
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError("ayar dosyasi bozuk (" + str(p) + "): " + str(exc)) from None
    return from_dict(raw, source=str(p))


def from_dict(raw: dict, source: str = "") -> Config:
    """Validate an already-parsed mapping (the file-less half of ``load``)."""
    unknown = sorted(set(raw) - set(_TABLES))
    if unknown:
        raise ConfigError("bilinmeyen bolum: " + ", ".join(unknown) +
                          "  (gecerli: " + ", ".join(_TABLES) + ")")
    weights = _weights(_table(raw, "weights"))
    thresholds = _thresholds(_table(raw, "thresholds"))
    soft_mult = _multipliers(_table(raw, "soft_multiplier"))
    soft_ids = _soft_ids(_table(raw, "soft_ids"))
    changed = tuple(name for name, value, default in (
        ("weights", weights, DEFAULTS.weights),
        ("thresholds", thresholds, DEFAULTS.thresholds),
        ("soft_multiplier", soft_mult, DEFAULTS.soft_mult),
        ("soft_ids", soft_ids, DEFAULTS.soft_ids),
    ) if value != default)
    return Config(weights=weights, thresholds=thresholds, soft_mult=soft_mult,
                  soft_ids=soft_ids, source=source, changed=changed)


# ---------------------------------------------------------------------------
# Validation - every failure names the offending key and what was expected.
# ---------------------------------------------------------------------------

def _table(raw: dict, name: str) -> dict:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError("[" + name + "] bir tablo olmali, " +
                          type(value).__name__ + " degil")
    return value


def _int(name: str, key: str, value, low: int, high: int) -> int:
    # bool is an int subclass in Python; `true` in a weight table is a mistake.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("[" + name + "] " + key + " tam sayi olmali, " +
                          type(value).__name__ + " degil")
    if not low <= value <= high:
        raise ConfigError("[" + name + "] " + key + " " + str(low) + ".." +
                          str(high) + " araliginda olmali, " + str(value) + " degil")
    return value


def _unknown_keys(name: str, table: dict, allowed) -> None:
    unknown = sorted(set(table) - set(allowed))
    if unknown:
        raise ConfigError("[" + name + "] bilinmeyen anahtar: " + ", ".join(unknown) +
                          "  (gecerli: " + ", ".join(allowed) + ")")


def _weights(table: dict) -> dict:
    out = {}
    for key, value in table.items():
        if key not in KNOWN_IDS:
            raise ConfigError("[weights] bilinmeyen gosterge id: " + key +
                              "  (gecerli id'ler: detector/mitre.py)")
        out[key] = _int("weights", key, value, 0, _MAX_WEIGHT)
    return out


def _thresholds(table: dict) -> dict:
    _unknown_keys("thresholds", table, DEFAULTS.thresholds)
    out = dict(DEFAULTS.thresholds)
    for key, value in table.items():
        out[key] = _int("thresholds", key, value, 0, scoring.MAX_SCORE)
    if not out["medium"] <= out["high"] <= out["critical"]:
        raise ConfigError("[thresholds] medium <= high <= critical olmali: " +
                          "medium=" + str(out["medium"]) + " high=" + str(out["high"]) +
                          " critical=" + str(out["critical"]))
    return out


def _multipliers(table: dict) -> dict:
    _unknown_keys("soft_multiplier", table, DEFAULTS.soft_mult)
    out = dict(DEFAULTS.soft_mult)
    for key, value in table.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError("[soft_multiplier] " + key + " sayi olmali, " +
                              type(value).__name__ + " degil")
        if not 0.0 <= float(value) <= 1.0:
            raise ConfigError("[soft_multiplier] " + key + " 0..1 araliginda olmali, " +
                              str(value) + " degil")
        out[key] = float(value)
    return out


def _soft_ids(table: dict) -> frozenset:
    _unknown_keys("soft_ids", table, _SOFT_KEYS)
    lists = {}
    for key in _SOFT_KEYS:
        value = table.get(key, [])
        if not isinstance(value, list):
            raise ConfigError("[soft_ids] " + key + " liste olmali, " +
                              type(value).__name__ + " degil")
        for item in value:
            if not isinstance(item, str) or item not in KNOWN_IDS:
                raise ConfigError("[soft_ids] " + key + " bilinmeyen gosterge id: " +
                                  str(item) + "  (gecerli id'ler: detector/mitre.py)")
        lists[key] = set(value)
    both = sorted(lists["add"] & lists["remove"])
    if both:
        raise ConfigError("[soft_ids] ayni id hem add hem remove icinde: " +
                          ", ".join(both))
    return frozenset((DEFAULTS.soft_ids | lists["add"]) - lists["remove"])
