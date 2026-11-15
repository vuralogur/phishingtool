"""Domain age over RDAP: "when was this domain registered?"

ONLINE ONLY. Nothing in this module runs unless the analysis was started with
``--online`` (see ``checks/threat_intel.py``). The request carries the
registrable domain and nothing else - no address, no URL path, no mail content.

``rdap.org`` is the IANA-bootstrap redirector: it answers with a redirect to the
registry that actually holds the domain, so one base URL covers every TLD that
speaks RDAP. Many country TLDs (``.tr`` among them) do not; for those there is
simply no answer, and no answer is never a finding.

Pure standard library (``urllib``). Every failure - timeout, 404, a registry
that omits the registration event - returns ``None``.
"""
from __future__ import annotations
import json
import re
import urllib.request
from datetime import datetime, timezone

URL = "https://rdap.org/domain/"
USER_AGENT = "phishingtool-rdap/1"
TIMEOUT = 8
MAX_BYTES = 512 * 1024

_DOMAIN = re.compile(r"[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+")

# One process, one question per domain: a batch run meets the same sender
# domain hundreds of times. Failures are remembered too - a registry that timed
# out once is not asked again for every mail in the folder.
_cache: dict = {}


def parse_registration(payload) -> datetime | None:
    """The ``registration`` event of an RDAP domain object, timezone-aware."""
    if not isinstance(payload, dict):
        return None
    for event in payload.get("events") or []:
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction", "")).strip().lower() != "registration":
            continue
        stamp = str(event.get("eventDate", "")).strip().replace("Z", "+00:00")
        try:
            when = datetime.fromisoformat(stamp)
        except ValueError:
            return None
        return when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    return None


def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read(MAX_BYTES)


def _ascii_domain(domain: str) -> str:
    """Lowercase A-label form, or "" when this is not something to send."""
    domain = (domain or "").strip().lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""
    return domain if _DOMAIN.fullmatch(domain) else ""


def registration_date(domain: str) -> datetime | None:
    """When the domain was registered; ``None`` when nobody could say."""
    domain = _ascii_domain(domain)
    if not domain:
        return None
    if domain not in _cache:
        try:
            _cache[domain] = parse_registration(
                json.loads(_http_get(URL + domain).decode("utf-8", "replace")))
        except Exception:
            _cache[domain] = None
    return _cache[domain]


def age_days(domain: str, now=None) -> int | None:
    """Whole days since registration; ``None`` when the date is unknown."""
    when = registration_date(domain)
    if when is None:
        return None
    return ((now or datetime.now(timezone.utc)) - when).days
