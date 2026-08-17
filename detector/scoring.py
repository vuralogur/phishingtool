"""Weighted, explainable, authentication-aware scoring: indicators -> verdict.

Two ideas keep false positives down on legitimate (often marketing) mail:

1. Trust multiplier - once a sender is authenticated (DMARC pass = the From
   domain is genuinely theirs), "soft" context signals (urgency wording, a
   generic greeting, a tracker redirect, a shortener) are mostly noise, so they
   are scaled down. "Hard" tradecraft (auth failure, spoofed identity, a
   credential-harvest form, an executable attachment) always keeps full weight -
   a compromised but authenticated account is still dangerous.

2. Corroboration - the verdict is driven by the HARD-signal subtotal. Soft
   signals alone (hard subtotal 0) never push past "low"; they only sharpen a
   verdict that hard evidence already justifies.

Because neither is a plain sum, every Result carries a ``Breakdown`` (subtotals,
the multiplier that was applied, and the verdict rule that fired) so the report
can answer "why this score" instead of asking the reader to trust it.

The constants below are the defaults, not the law: ``score(config=...)`` takes a
``detector.config.Config`` and reads the soft set, the multipliers, the
thresholds and per-indicator weights from it instead. Nothing is imported from
that module here - the object is only ever read - so the two stay independent.
"""
from __future__ import annotations
from dataclasses import dataclass, replace

from .indicators import SEVERITY_ORDER
from .mitre import summary as technique_summary

MAX_SCORE = 100

# "Soft" = context/noise that legitimate senders routinely trip. Everything not
# listed here is treated as HARD (full weight, drives the verdict) - defaulting
# unknown/new indicators to hard is the safer choice for a security tool.
SOFT_IDS = {
    # content tone
    "urgency_language", "generic_greeting",
    # url noise common in marketing / ESP infrastructure
    "url_shortener", "suspicious_tld", "excessive_subdomains", "at_in_url",
    "punycode_domain", "open_redirect", "random_host",
    # attachment "capability" (not confirmed malicious)
    "archive_attachment", "macro_document", "mime_extension_mismatch",
    # html quirks marketing HTML also produces
    "meta_refresh_redirect", "base_tag_href", "hidden_iframe", "hidden_text",
    "obfuscated_script",
    # envelope mismatch is normal for ESP-sent mail (envelope = ESP, From = brand)
    "from_returnpath_mismatch",
    # informational / online-record absence
    "no_spf_record", "no_dmarc_record", "no_received_headers",
    "private_origin_ip", "qr_code_url", "msg_no_transport_headers",
    # A lower Authentication-Results disagreeing with the authoritative one is
    # normal after a forward; it explains the auth line, it must not drive it.
    "auth_results_conflict",
    # Already acted on where it matters (the trust discount is withheld); as a
    # score it would double-count the same observation.
    "auth_claim_unverifiable",
}

# Soft-signal weight multiplier by authentication level.
SOFT_MULT = {"pass": 0.3, "partial": 0.6, "fail": 1.0, "none": 1.0}

# Verdict cut-offs, all read against the HARD subtotal except soft_pileup (which
# is read against the capped total) - see the ladder at the end of score().
THRESHOLDS = {
    "medium": 10,
    "high": 22,
    "critical": 45,
    "soft_pileup": 30,   # hard > 0 and total >= this -> medium
    "allowlist": 22,     # trusted sender staying under this -> low
}


@dataclass
class Breakdown:
    """How the score was assembled - answers "why this number, why this verdict".

    hard/soft are subtotals; ``soft`` is ``soft_raw * multiplier``. ``reason`` is
    the verdict rule that fired (a stable key; the report translates it).
    ``config_source``/``config_changed`` say whether the numbers above came from
    the built-in model ("" = yes) or from an override file, and which tables of
    it differed - a score is only reproducible if you know which model made it.
    """
    hard: float
    soft_raw: float
    soft: float
    multiplier: float
    auth_level: str
    hard_count: int
    soft_count: int
    trusted: bool
    capped: bool
    reason: str
    config_source: str = ""
    config_changed: tuple = ()

    def to_dict(self) -> dict:
        return {
            "hard": round(self.hard, 2),
            "soft_raw": round(self.soft_raw, 2),
            "soft": round(self.soft, 2),
            "multiplier": self.multiplier,
            "auth_level": self.auth_level,
            "hard_count": self.hard_count,
            "soft_count": self.soft_count,
            "trusted": self.trusted,
            "capped": self.capped,
            "reason": self.reason,
            # null = the built-in model; otherwise which file changed what.
            "config": ({"source": self.config_source,
                        "changed": list(self.config_changed)}
                       if self.config_source else None),
        }


@dataclass
class Result:
    verdict: str
    score: int
    max_score: int
    auth: dict
    indicators: list
    breakdown: "Breakdown | None" = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "max_score": self.max_score,
            "auth": self.auth,
            "breakdown": self.breakdown.to_dict() if self.breakdown else None,
            # ATT&CK roll-up: which techniques this mail used, so a consumer does
            # not have to group the indicator list itself.
            "techniques": technique_summary(self.indicators),
            "indicators": [i.to_dict() for i in self.indicators],
        }


def auth_level(auth: dict) -> str:
    """Collapse the SPF/DKIM/DMARC summary into a single trust level."""
    dmarc = auth.get("dmarc", "none")
    spf = auth.get("spf", "none")
    dkim = auth.get("dkim", "none")
    if dmarc == "pass":
        return "pass"
    if dmarc == "fail" or "fail" in (spf, dkim) or spf == "softfail":
        return "fail"
    if spf == "pass" or dkim == "pass":
        return "partial"
    return "none"


def score(indicators, auth, from_rdom="", level=None, allowlist=None,
          config=None) -> Result:
    allowlist = allowlist or set()
    level = level or auth_level(auth)
    # An override file, when given, replaces the whole model - not just parts of
    # it - so a config'd run and a default run take the same code path.
    soft_ids = config.soft_ids if config else SOFT_IDS
    thresholds = config.thresholds if config else THRESHOLDS
    mult = (config.soft_mult if config else SOFT_MULT).get(level, 1.0)

    weights = config.weights if config else {}
    if weights:
        # replace(), not mutation: the indicator objects belong to the caller,
        # and a check that is re-scored under two configs must not drift.
        indicators = [replace(i, weight=weights[i.id]) if i.id in weights else i
                      for i in indicators]

    hard_sum = 0.0
    soft_raw = 0.0
    hard_n = soft_n = 0
    for i in indicators:
        if i.id in soft_ids:
            soft_raw += i.weight
            soft_n += 1
        else:
            hard_sum += i.weight
            hard_n += 1
    soft_sum = soft_raw * mult

    raw_total = int(round(hard_sum + soft_sum))
    total = min(raw_total, MAX_SCORE)

    # Authenticated AND explicitly trusted domain: don't nag unless real
    # tradecraft is present.
    trusted = level == "pass" and bool(from_rdom) and from_rdom in allowlist

    if trusted and hard_sum < thresholds["allowlist"]:
        verdict, reason = "low", "allowlist"
    elif hard_sum >= thresholds["critical"]:
        verdict, reason = "critical", "hard_critical"
    elif hard_sum >= thresholds["high"]:
        verdict, reason = "high", "hard_high"
    elif hard_sum >= thresholds["medium"]:
        verdict, reason = "medium", "hard_medium"
    elif hard_sum > 0 and total >= thresholds["soft_pileup"]:
        # a hard signal exists and soft noise piles on top
        verdict, reason = "medium", "soft_pileup"
    else:
        verdict = "low"
        reason = "weak_hard_evidence" if hard_sum > 0 else "no_hard_evidence"

    breakdown = Breakdown(
        hard=hard_sum, soft_raw=soft_raw, soft=soft_sum, multiplier=mult,
        auth_level=level, hard_count=hard_n, soft_count=soft_n,
        trusted=trusted, capped=raw_total > MAX_SCORE, reason=reason,
        config_source=getattr(config, "source", ""),
        config_changed=tuple(getattr(config, "changed", ())),
    )
    ordered = sorted(
        indicators,
        key=lambda i: (-SEVERITY_ORDER.get(i.severity, 0), -i.weight),
    )
    return Result(verdict, total, MAX_SCORE, auth, ordered, breakdown)
