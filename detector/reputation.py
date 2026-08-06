"""Optional reputation lookups (VirusTotal). Online + API key required.

PRIVACY: this sends the email's link domains to a third-party service.
It only runs when online=True AND the VT_API_KEY environment variable is set.
"""
from __future__ import annotations
import os
from urllib.parse import urlparse

from .indicators import Indicator
from .util import registered_domain


def run(email, online=False, ctx=None):
    if not online:
        return []
    key = os.environ.get("VT_API_KEY")
    if not key:
        return []
    try:
        import requests  # type: ignore
    except Exception:
        return []

    out = []
    hosts = set()
    for link in email.links:
        h = urlparse(link.href).hostname
        if h:
            hosts.add(registered_domain(h.lower()))

    for dom in list(hosts)[:5]:
        try:
            r = requests.get(
                "https://www.virustotal.com/api/v3/domains/" + dom,
                headers={"x-apikey": key}, timeout=8,
            )
            if r.status_code == 200:
                stats = (r.json().get("data", {})
                         .get("attributes", {})
                         .get("last_analysis_stats", {}))
                mal = int(stats.get("malicious", 0))
                if mal > 0:
                    out.append(Indicator("vt_flagged", "reputation", "critical", 25,
                        "VirusTotal: " + dom + " " + str(mal) + " motor tarafindan zararli isaretli",
                        "Domain itibar servislerinde zararli olarak biliniyor."))
        except Exception:
            pass
    return out
