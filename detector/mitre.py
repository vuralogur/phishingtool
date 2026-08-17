"""MITRE ATT&CK technique tags for the indicators this tool raises.

An indicator id answers "what did we see"; a technique id answers "what is the
adversary doing" in the vocabulary the rest of the SOC already speaks - so a
report can be pivoted against detections, playbooks and coverage maps instead of
staying a tool-private slug.

The mapping is curated and deliberately conservative:

* **One technique per indicator** - the closest match, not every technique the
  mail could belong to. Every phishing mail is T1566 at the top level; stamping
  that on all 50 indicators would carry no information.
* **Not everything maps.** ``vt_flagged`` is a third-party verdict and
  ``no_spf_record`` describes the *impersonated* domain's own posture - neither
  is adversary tradecraft, so both sit in ``NO_TECHNIQUE``. Being explicitly
  unmapped is what lets the drift test tell them apart from "forgotten".

Tagging happens in ``Indicator.__post_init__``, so every indicator produced
anywhere (CLI, GUI, bench, a direct check call) carries it - there is no
separate stamping step that a new code path could skip.

Reference: https://attack.mitre.org/techniques/enterprise/
"""
from __future__ import annotations

_BASE = "https://attack.mitre.org/techniques/"

# Technique id -> ATT&CK display name (sub-techniques keep the parent prefix).
NAMES = {
    "T1027": "Obfuscated Files or Information",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1036": "Masquerading",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1056.003": "Input Capture: Web Portal Capture",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1598": "Phishing for Information",
    "T1656": "Impersonation",
}

# Indicator id -> technique id.
TECHNIQUES = {
    # Sender identity: the mail claims to come from someone it does not.
    "spf_fail": "T1656",
    "spf_softfail": "T1656",
    "spf_live_fail": "T1656",
    "spf_live_softfail": "T1656",
    "dkim_fail": "T1656",
    "dkim_verify_fail": "T1656",
    "dmarc_fail": "T1656",
    "dmarc_policy_violation": "T1656",
    "from_replyto_mismatch": "T1656",
    "from_returnpath_mismatch": "T1656",
    "display_name_spoof": "T1656",
    "brand_impersonation": "T1656",

    # Attacker-registered domains: typosquats, homoglyphs, throwaway hosts.
    # ATT&CK lists exactly this tradecraft under Acquire Infrastructure: Domains.
    "lookalike_domain": "T1583.001",
    "combosquat_domain": "T1583.001",
    "brand_in_subdomain": "T1583.001",
    "confusable_brand": "T1583.001",
    "homograph_domain": "T1583.001",
    "punycode_domain": "T1583.001",
    "suspicious_tld": "T1583.001",
    "excessive_subdomains": "T1583.001",
    "random_host": "T1583.001",

    # The link itself is the delivery vehicle (QR = the same link, hidden in
    # an image so text-layer filters never see it).
    "anchor_href_mismatch": "T1566.002",
    "ip_url": "T1566.002",
    "at_in_url": "T1566.002",
    "url_shortener": "T1566.002",
    "open_redirect": "T1566.002",
    "qr_code_url": "T1566.002",
    "qr_suspicious_url": "T1566.002",

    # Body HTML that steers the reader somewhere else.
    "meta_refresh_redirect": "T1204.001",
    "base_tag_href": "T1036",

    # Body HTML built to be unreadable to the reader or the scanner.
    "obfuscated_script": "T1027",
    "hidden_text": "T1027",
    "hidden_iframe": "T1027",

    # Credential harvesting: a login form inside the mail, posting outward.
    "form_external_action": "T1056.003",
    "html_password_input": "T1056.003",
    "credential_request": "T1598",

    # Social-engineering pretext - the phishing lure itself, no sub-technique.
    "urgency_language": "T1566",
    "generic_greeting": "T1566",

    # The attachment is the delivery vehicle.
    "dangerous_attachment": "T1566.001",
    "macro_document": "T1566.001",
    "archive_attachment": "T1566.001",

    # The attachment lies about what it is.
    "double_extension": "T1036.007",
    "mime_extension_mismatch": "T1036.008",

    # Confirmed active content inside the attachment.
    "html_smuggling": "T1027.006",
    "macro_detected": "T1059.005",
    "macro_autoexec": "T1059.005",
    "pdf_launch_action": "T1204.002",
    "pdf_active_content": "T1204.002",
}

# Deliberately unmapped: a reputation verdict and hygiene/forensic observations
# about the sending infrastructure. None of them is a thing the adversary *does*,
# so inventing a technique for them would pollute the coverage map.
NO_TECHNIQUE = frozenset({
    "vt_flagged",
    "no_spf_record",
    "no_dmarc_record",
    "no_received_headers",
    "private_origin_ip",
    # A gap in what Outlook stored in the .msg - a fact about the file format.
    "msg_no_transport_headers",
    # Two Authentication-Results headers disagreeing is exactly what a forward
    # produces, so it describes the mail's path, not the adversary's tradecraft.
    "auth_results_conflict",
    # "The header says pass and nothing backs it up" is a statement about what
    # this file can prove, not about a technique the adversary used.
    "auth_claim_unverifiable",
})


def url(technique: str) -> str:
    """Canonical ATT&CK page: T1566.002 -> .../techniques/T1566/002/."""
    return _BASE + technique.replace(".", "/") + "/" if technique else ""


def lookup(indicator_id: str) -> tuple:
    """``(technique id, display name)`` for an indicator; ``("", "")`` if unmapped."""
    tid = TECHNIQUES.get(indicator_id, "")
    return tid, NAMES.get(tid, "")


def summary(indicators) -> list:
    """Techniques seen in one analysis, each with the indicators that raised it.

    Sorted by technique id so two runs of the same mail render identically.
    """
    grouped = {}
    for i in indicators:
        tid = getattr(i, "technique", "")
        if tid:
            grouped.setdefault(tid, set()).add(i.id)
    return [{"id": tid, "name": NAMES.get(tid, ""), "url": url(tid),
             "indicators": sorted(grouped[tid])}
            for tid in sorted(grouped)]
