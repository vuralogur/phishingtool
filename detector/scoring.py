"""Weighted, explainable, authentication-aware scoring: indicators -> verdict.

Two ideas keep false positives down on legitimate (often marketing) mail:

1. Trust multiplier - once a sender is authenticated (DMARC pass = the From
   domain is genuinely theirs), "soft" context signals (urgency wording, a
   generic greeting, a tracker redirect, a shortener) are mostly noise, so they
   are scaled down. "Hard" tradecraft (auth failure, spoofed identity, a
   credential-harvest form, an executable attachment) always keeps full weight -
   a compromised but authenticated account is still dangerous.

2. Corroboration - the verdict is driven by the HARD-signal subtotal. Soft
   signals sharpen a verdict that hard evidence already justifies; on their own
   (hard subtotal 0) they stay "low", with one narrow exception: several
   distinct carrier signals (``STACK_IDS``) from a sender that is not
   DMARC-authenticated reach "medium" - never higher.

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
    # Same name under another ending: a squat, or the brand's own side domain.
    # Generic-word names (apple, amazon, turkiye) make it too noisy to stand alone.
    "tld_swap_domain",
    # Free hosting and a brand domain in a URL path: how throwaway phishing
    # pages are addressed - and how small projects and web archives are too.
    "free_hosting_url", "brand_in_path",
    # A "RE:" on a mail that replies to nothing; some clients drop the headers.
    "fake_reply_subject",
    # Another page on the same host is on a threat list. The host may be the
    # attacker's alone - or a service thousands of unrelated sites share.
    "threat_feed_neighbor",
    # attachment "capability" (not confirmed malicious)
    "archive_attachment", "macro_document", "mime_extension_mismatch",
    "pdf_embedded_file",
    # Bytes that disagree with the extension without being an executable: a
    # renamed archive or a page saved under the wrong name is sloppy far more
    # often than hostile. (An executable behind a document name is hard.)
    "content_extension_mismatch",
    # A password-protected archive: the standard way to walk malware past a
    # scanner, and the standard way to mail payroll. Not evidence alone.
    "archive_encrypted",
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
    # Likewise: the discount is already withheld when every pass is for another
    # domain; and a brand address with no verdict in the file proves nothing.
    "auth_pass_unaligned", "brand_domain_unverified",
}

# Soft-signal weight multiplier by authentication level.
SOFT_MULT = {"pass": 0.3, "partial": 0.6, "fail": 1.0, "none": 1.0}

# Verdict cut-offs, all read against the HARD subtotal except soft_pileup (which
# is read against the capped total) and the soft_stack pair (read against the
# STACK_IDS signals only) - see the ladder at the end of score().
THRESHOLDS = {
    "medium": 10,
    "high": 22,
    "critical": 45,
    "soft_pileup": 30,   # hard > 0 and total >= this -> medium
    "allowlist": 22,     # trusted sender staying under this -> low
    "auth_cap": 20,      # most the auth-failure family may add to the hard subtotal
    # Hard evidence below "medium", sender not DMARC-authenticated: this many
    # distinct STACK_IDS signals (0 = rule off) worth this many points -> medium.
    "soft_stack_min": 2,
    "soft_stack": 15,
}

# The one way soft signals reach "medium" on their own. Most of SOFT_IDS is what
# bulk mail produces by construction - urgent wording, a generic greeting, a
# click-tracker redirect on a random ESP host, a hidden preheader - and a
# perfectly legitimate newsletter saved without its Authentication-Results
# scores as high on those as a phish does, so no points threshold over the whole
# soft set can separate the two. The ids below are different in kind: they
# describe where the mail leads or what it carries, and ordinary mail plumbing
# does not emit them. One of them is still an anecdote (a t.co link, an internal
# .docm); two together, from a sender nobody vouched for, is a pattern.
# Deliberately absent: tone (urgency_language, generic_greeting), tracker
# plumbing (open_redirect, random_host, excessive_subdomains), hidden_text,
# archive_attachment, pdf_embedded_file (e-invoices embed XML), and every
# auth-category note - "not authenticated" is this rule's precondition, counting
# it again as evidence would use the same fact twice.
STACK_IDS = frozenset({
    "url_shortener", "suspicious_tld", "punycode_domain", "at_in_url",
    "tld_swap_domain", "free_hosting_url", "brand_in_path",
    "macro_document", "mime_extension_mismatch", "content_extension_mismatch",
    "archive_encrypted", "qr_code_url",
    "meta_refresh_redirect", "base_tag_href", "hidden_iframe",
    "obfuscated_script",
})

# One root cause, many headers. A mail that fails DMARC has by definition failed
# aligned SPF and aligned DKIM, and --online re-measures the same three things -
# six indicators, one fact: "this sender is not authenticated as the From
# domain". Summed, that single fact reached "high" on its own (a forwarded
# mailing-list post breaks all three), so the family is capped: alone it earns a
# "medium", and it takes independent evidence to go further.
AUTH_FAIL_IDS = frozenset({
    "spf_fail", "spf_softfail", "dkim_fail", "dmarc_fail",
    "spf_live_fail", "spf_live_softfail", "dkim_verify_fail",
    "dmarc_policy_violation",
})


@dataclass
class Breakdown:
    """How the score was assembled - answers "why this number, why this verdict".

    hard/soft are subtotals; ``soft`` is ``soft_raw * multiplier``. ``reason`` is
    the verdict rule that fired (a stable key; the report translates it).
    ``config_source``/``config_changed`` say whether the numbers above came from
    the built-in model ("" = yes) or from an override file, and which tables of
    it differed - a score is only reproducible if you know which model made it.
    ``auth_raw`` is what the auth-failure family added up to before its cap and
    ``auth_trimmed`` how much the cap took off; ``hard`` is already net of it.
    ``stack``/``stack_ids`` are set only when the ``soft_stack`` rule decided the
    verdict: the points it counted and the indicators they came from.
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
    auth_raw: float = 0.0
    auth_trimmed: float = 0.0
    stack: float = 0.0
    stack_ids: tuple = ()

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
            # 0 unless the auth-failure family hit its cap (see AUTH_FAIL_IDS).
            "auth_raw": round(self.auth_raw, 2),
            "auth_trimmed": round(self.auth_trimmed, 2),
            # 0 / [] unless reason == "soft_stack" (see STACK_IDS).
            "stack": round(self.stack, 2),
            "stack_ids": list(self.stack_ids),
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
    auth_raw = 0.0
    hard_n = soft_n = 0
    stack = 0.0
    stack_ids = []
    for i in indicators:
        soft = i.id in soft_ids
        # Distinct ids: the same signal reported twice is still one signal.
        # Scaled like any soft signal, so a half-trusted sender ("partial") needs
        # a taller stack than an unknown one. An id a config promoted to hard
        # still counts, at full weight - making a signal stricter must never
        # lower a verdict.
        if i.id in STACK_IDS and i.weight > 0 and i.id not in stack_ids:
            stack += i.weight * (mult if soft else 1.0)
            stack_ids.append(i.id)
        if soft:
            soft_raw += i.weight
            soft_n += 1
        else:
            hard_sum += i.weight
            hard_n += 1
            if i.id in AUTH_FAIL_IDS:
                auth_raw += i.weight
    # .get(): a hand-built policy object written before the cap existed still works.
    auth_cap = thresholds.get("auth_cap", THRESHOLDS["auth_cap"])
    auth_trimmed = max(0.0, auth_raw - auth_cap)
    hard_sum -= auth_trimmed
    soft_sum = soft_raw * mult

    raw_total = int(round(hard_sum + soft_sum))
    total = min(raw_total, MAX_SCORE)

    # Authenticated AND explicitly trusted domain: don't nag unless real
    # tradecraft is present.
    trusted = level == "pass" and bool(from_rdom) and from_rdom in allowlist

    # A DMARC-authenticated sender is out of the rule altogether - there, soft
    # signals alone stay "low" as they always have. No "hard == 0" condition: the
    # ladder below only gets here when hard evidence is too weak to decide, and
    # a weak hard signal on top of a stack must not score lower than the stack.
    stack_min = thresholds.get("soft_stack_min", THRESHOLDS["soft_stack_min"])
    stacked = (level != "pass" and stack_min > 0
               and len(stack_ids) >= stack_min
               and stack >= thresholds.get("soft_stack", THRESHOLDS["soft_stack"]))

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
    elif stacked:
        # hard evidence absent or weak, but several carrier signals from an
        # unvouched sender
        verdict, reason = "medium", "soft_stack"
    else:
        verdict = "low"
        reason = "weak_hard_evidence" if hard_sum > 0 else "no_hard_evidence"

    breakdown = Breakdown(
        hard=hard_sum, soft_raw=soft_raw, soft=soft_sum, multiplier=mult,
        auth_level=level, hard_count=hard_n, soft_count=soft_n,
        trusted=trusted, capped=raw_total > MAX_SCORE, reason=reason,
        config_source=getattr(config, "source", ""),
        config_changed=tuple(getattr(config, "changed", ())),
        auth_raw=auth_raw if auth_trimmed else 0.0, auth_trimmed=auth_trimmed,
        stack=stack if reason == "soft_stack" else 0.0,
        stack_ids=tuple(stack_ids) if reason == "soft_stack" else (),
    )
    ordered = sorted(
        indicators,
        key=lambda i: (-SEVERITY_ORDER.get(i.severity, 0), -i.weight),
    )
    return Result(verdict, total, MAX_SCORE, auth, ordered, breakdown)
