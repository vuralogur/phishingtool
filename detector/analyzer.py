"""Orchestrator: parse -> run all checks -> score. Reused by CLI and any UI."""
from __future__ import annotations
import os
from pathlib import Path

from . import config as _config
from . import parser as _parser
from . import reputation
from .checks import (
    headers, urls, content, attachments, auth_verify,
    html_forensics, attachment_deep, qr, url_deep,
)
from .scoring import score, auth_level
from .util import registered_domain

# Dictionaries ship inside the package so `pip install phishingtool` works from
# any directory. Point PHISHINGTOOL_DATA (or --data-dir) at your own copy to
# override them without touching the installed files.
_DATA = Path(__file__).resolve().parent / "data"
_DATA_ENV = "PHISHINGTOOL_DATA"


def _load_brands(path: Path) -> dict:
    brands = {}
    if not path.exists():
        return brands
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, doms = line.partition(",")
        name = name.strip().lower()
        domains = {d.strip().lower() for d in doms.split(";") if d.strip()}
        if name:
            brands[name] = domains
    return brands


def _load_set(path: Path) -> set:
    s = set()
    if not path.exists():
        return s
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            s.add(line)
    return s


def resolve_data_dir(data_dir=None) -> Path:
    """Where the dictionaries live: argument > PHISHINGTOOL_DATA > bundled."""
    if data_dir:
        return Path(data_dir)
    env = os.environ.get(_DATA_ENV, "").strip()
    return Path(env) if env else _DATA


def build_context(data_dir=None, config=None) -> dict:
    """Dictionaries + scoring policy, loaded once and reused for every mail.

    ``config`` is a path, an already-built ``config.Config``, or None; with
    nothing given and no PHISHINGTOOL_CONFIG set, the built-in scoring model
    applies, so the default run is unchanged.
    A broken file raises ``config.ConfigError`` here rather than silently
    scoring the whole batch with defaults nobody asked for.
    """
    d = resolve_data_dir(data_dir)
    return {
        "brands": _load_brands(d / "brands.txt"),
        "suspicious_tlds": _load_set(d / "suspicious_tlds.txt"),
        "urgency": sorted(_load_set(d / "urgency_keywords.txt")),
        "allowlist": _load_set(d / "trusted_domains.txt"),
        "config": _config.resolve(config),
    }


def analyze(email, online=False, ctx=None):
    ctx = ctx if ctx is not None else build_context()

    # Trust context: authentication level + sender's registrable domain. Checks
    # read from_rdom/auth_level to suppress first-party (sender's own tracker)
    # noise; scoring uses them to discount soft signals from proven senders.
    auth = headers.summary(email)
    level = auth_level(auth)
    if headers.unverifiable_auth(email):
        # A "pass" that no server stamped is the sender's own claim. The report
        # still shows what the header says (and headers.py raises an indicator
        # about it), but the score must not hand out the trust discount for it.
        level = "none"
    from_rdom = registered_domain(email.from_domain)
    ctx = {**ctx, "from_rdom": from_rdom, "auth_level": level}

    indicators = []
    indicators += headers.run(email, online, ctx)
    indicators += auth_verify.run(email, online, ctx)
    indicators += urls.run(email, online, ctx)
    indicators += url_deep.run(email, online, ctx)
    indicators += content.run(email, online, ctx)
    indicators += html_forensics.run(email, online, ctx)
    indicators += attachments.run(email, online, ctx)
    indicators += attachment_deep.run(email, online, ctx)
    indicators += qr.run(email, online, ctx)
    indicators += reputation.run(email, online, ctx)
    return score(indicators, auth, from_rdom=from_rdom, level=level,
                 allowlist=ctx.get("allowlist"), config=ctx.get("config"))


def analyze_file(path, online=False, ctx=None):
    return analyze(_parser.parse_file(path), online, ctx)


def analyze_text(text, online=False, ctx=None):
    return analyze(_parser.parse_text(text), online, ctx)
