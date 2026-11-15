"""Orchestrator: parse -> run all checks -> score. Reused by CLI and any UI."""
from __future__ import annotations
import os
from pathlib import Path

from . import config as _config
from . import feeds as _feeds
from . import parser as _parser
from . import reputation
from .checks import (
    headers, urls, content, attachments, auth_verify,
    html_forensics, attachment_deep, qr, url_deep, social, threat_intel,
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


def build_context(data_dir=None, config=None, feeds_dir=None) -> dict:
    """Dictionaries + scoring policy, loaded once and reused for every mail.

    ``config`` is a path, an already-built ``config.Config``, or None; with
    nothing given and no PHISHINGTOOL_CONFIG set, the built-in scoring model
    applies, so the default run is unchanged.
    A broken file raises ``config.ConfigError`` here rather than silently
    scoring the whole batch with defaults nobody asked for.

    ``feeds_dir`` is the folder of downloaded threat lists (``feeds.py``):
    None = the default / PHISHINGTOOL_FEEDS folder, ``False`` = use no lists.
    The lists are read from disk here and never fetched; a machine that has not
    run ``phishingtool feeds update`` has none and nothing changes.
    """
    d = resolve_data_dir(data_dir)
    brands = _load_brands(d / "brands.txt")
    # The organisation's own domains are protected exactly like a brand's: a
    # look-alike of them, or an unauthenticated mail claiming to come from them,
    # is caught by the checks that already exist. Empty file = nothing changes.
    own = _load_set(d / "own_domains.txt")
    for domain in own:
        brands.setdefault(domain.split(".")[0], set()).add(domain)
    return {
        "brands": brands,
        "own_domains": own,
        "vip_names": sorted(_load_set(d / "vip_names.txt")),
        # Like lure_words below: a custom --data-dir without the file falls back
        # to the bundled list instead of silently switching the check off.
        "free_hosting": (_load_set(d / "free_hosting.txt")
                         or _load_set(_DATA / "free_hosting.txt")),
        "suspicious_tlds": _load_set(d / "suspicious_tlds.txt"),
        "urgency": sorted(_load_set(d / "urgency_keywords.txt")),
        "allowlist": _load_set(d / "trusted_domains.txt"),
        # Newer than the other dictionaries: a --data-dir folder made before it
        # existed has no such file, and an empty set would silently switch
        # combosquat detection off - so that case falls back to the bundled list.
        "lure_words": (_load_set(d / "lure_words.txt")
                       or _load_set(_DATA / "lure_words.txt")),
        "config": _config.resolve(config),
        "feeds": (_feeds.FeedSet() if feeds_dir is False
                  else _feeds.load(feeds_dir)),
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
    if level in ("pass", "partial") and headers.alignment(email)[0] == "unaligned":
        # Every passing result vouches for some other domain (the attacker's own
        # mail server passes SPF and DKIM for the attacker's own domain). That
        # authenticates them, not the From address, so it buys no trust either.
        level = "none"
    from_rdom = registered_domain(email.from_domain)
    ctx = {**ctx, "from_rdom": from_rdom, "auth_level": level}

    indicators = []
    indicators += headers.run(email, online, ctx)
    indicators += auth_verify.run(email, online, ctx)
    indicators += urls.run(email, online, ctx)
    indicators += url_deep.run(email, online, ctx)
    indicators += content.run(email, online, ctx)
    indicators += social.run(email, online, ctx)
    indicators += html_forensics.run(email, online, ctx)
    indicators += attachments.run(email, online, ctx)
    indicators += attachment_deep.run(email, online, ctx)
    indicators += qr.run(email, online, ctx)
    indicators += threat_intel.run(email, online, ctx)
    indicators += reputation.run(email, online, ctx)
    return score(indicators, auth, from_rdom=from_rdom, level=level,
                 allowlist=ctx.get("allowlist"), config=ctx.get("config"))


def analyze_file(path, online=False, ctx=None):
    return analyze(_parser.parse_file(path), online, ctx)


def analyze_text(text, online=False, ctx=None):
    return analyze(_parser.parse_text(text), online, ctx)
