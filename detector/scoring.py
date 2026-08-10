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
"""
from __future__ import annotations
from dataclasses import dataclass

from .indicators import SEVERITY_ORDER

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
    "private_origin_ip", "qr_code_url",
}

# Soft-signal weight multiplier by authentication level.
_SOFT_MULT = {"pass": 0.3, "partial": 0.6, "fail": 1.0, "none": 1.0}


@dataclass
class Breakdown:
    """How the score was assembled - answers "why this number, why this verdict".

    hard/soft are subtotals; ``soft`` is ``soft_raw * multiplier``. ``reason`` is
    the verdict rule that fired (a stable key; the report translates it).
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


def score(indicators, auth, from_rdom="", level=None, allowlist=None) -> Result:
    allowlist = allowlist or set()
    level = level or auth_level(auth)
    mult = _SOFT_MULT.get(level, 1.0)

    hard_sum = 0.0
    soft_raw = 0.0
    hard_n = soft_n = 0
    for i in indicators:
        if i.id in SOFT_IDS:
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

    if trusted and hard_sum < 22:
        verdict, reason = "low", "allowlist"
    elif hard_sum >= 45:
        verdict, reason = "critical", "hard_critical"
    elif hard_sum >= 22:
        verdict, reason = "high", "hard_high"
    elif hard_sum >= 10:
        verdict, reason = "medium", "hard_medium"
    elif hard_sum > 0 and total >= 30:
        # a hard signal exists and soft noise piles on top
        verdict, reason = "medium", "soft_pileup"
    else:
        verdict = "low"
        reason = "weak_hard_evidence" if hard_sum > 0 else "no_hard_evidence"

    breakdown = Breakdown(
        hard=hard_sum, soft_raw=soft_raw, soft=soft_sum, multiplier=mult,
        auth_level=level, hard_count=hard_n, soft_count=soft_n,
        trusted=trusted, capped=raw_total > MAX_SCORE, reason=reason,
    )
    ordered = sorted(
        indicators,
        key=lambda i: (-SEVERITY_ORDER.get(i.severity, 0), -i.weight),
    )
    return Result(verdict, total, MAX_SCORE, auth, ordered, breakdown)
