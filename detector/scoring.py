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
class Result:
    verdict: str
    score: int
    max_score: int
    auth: dict
    indicators: list

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "max_score": self.max_score,
            "auth": self.auth,
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
    soft_sum = 0.0
    for i in indicators:
        if i.id in SOFT_IDS:
            soft_sum += i.weight * mult
        else:
            hard_sum += i.weight

    total = min(int(round(hard_sum + soft_sum)), MAX_SCORE)

    # Authenticated AND explicitly trusted domain: don't nag unless real
    # tradecraft is present.
    trusted = level == "pass" and from_rdom and from_rdom in allowlist

    if trusted and hard_sum < 22:
        verdict = "low"
    elif hard_sum >= 45:
        verdict = "critical"
    elif hard_sum >= 22:
        verdict = "high"
    elif hard_sum >= 10:
        verdict = "medium"
    elif hard_sum > 0 and total >= 30:
        # a hard signal exists and soft noise piles on top
        verdict = "medium"
    else:
        verdict = "low"

    ordered = sorted(
        indicators,
        key=lambda i: (-SEVERITY_ORDER.get(i.severity, 0), -i.weight),
    )
    return Result(verdict, total, MAX_SCORE, auth, ordered)
