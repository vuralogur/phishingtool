"""Threat lists: downloaded on request, matched offline.

Two halves that never meet:

* ``update()`` is the only code here that touches the network. It runs when the
  user types ``phishingtool feeds update`` and at no other time. It downloads
  public block lists and sends nothing but the request itself - no mail, no
  address, no domain taken from a mail.
* ``load()`` / ``FeedSet.lookup()`` read the downloaded files from disk. An
  analysis that finds a link on a list has asked nobody anything.

So a default run stays offline, and a machine that never ran ``feeds update``
has no lists: ``load()`` returns an empty (falsy) set and no indicator can fire.

Sources (``SOURCES``):

  openphish  community feed, one phishing URL per line
  usom       Turkey's national CERT list (siberguvenlik.gov.tr API): domains,
             IPs and URLs. Only the last ``days`` days are fetched - the full
             list is half a million rows
  urlhaus    abuse.ch malware-distribution URLs. Needs a free Auth-Key in
             URLHAUS_AUTH_KEY and is skipped without one

Every other ``*.txt`` in the folder is read as well - one URL, domain or IP per
line - so an organisation can drop in its own block list.

On disk a list is plain text, one normalised entry per line (``url_key``):
``host`` when a whole host is listed, ``host/path?query`` when one address is.

Where the folder is: ``--feeds-dir`` > ``PHISHINGTOOL_FEEDS`` > the per-user
cache directory (``%LOCALAPPDATA%\\phishingtool\\feeds`` on Windows,
``~/.cache/phishingtool/feeds`` elsewhere).
"""
from __future__ import annotations
import csv
import json
import os
import re
import urllib.request
from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .util import canonical_ip, registered_domain

SOURCES = ("openphish", "usom", "urlhaus")
LABELS = {"openphish": "OpenPhish", "usom": "USOM", "urlhaus": "URLhaus"}

_ENV = "PHISHINGTOOL_FEEDS"
URLHAUS_KEY_ENV = "URLHAUS_AUTH_KEY"

OPENPHISH_URL = "https://openphish.com/feed.txt"
USOM_URL = "https://siberguvenlik.gov.tr/api/address/index"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"

USER_AGENT = "phishingtool-feeds/1"
TIMEOUT = 30
MAX_BYTES = 64 * 1024 * 1024    # one response; a list is a few MB at most
USOM_DAYS = 30                  # default window for `feeds update`
USOM_PAGE_SIZE = 5000
USOM_MAX_PAGES = 60             # 300k rows: a ceiling, not a target
STALE_DAYS = 7                  # older than this and the report says so

_AUTH_KEY = re.compile(r"[A-Za-z0-9]+")
# "mailto:x@y" has a scheme and no "//"; "host:8080/x" has a port, not a scheme.
_OTHER_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:(?!\d)")
_HTTP = ("http://", "https://")


class FeedError(Exception):
    """A source answered with something that is not its list."""


class FeedSkipped(Exception):
    """A source that cannot be fetched on this machine (no key) - not a failure."""


# --------------------------------------------------------------------------
# normalisation
# --------------------------------------------------------------------------

def url_key(value: str) -> str:
    """The form in which a list entry and a mail link are compared.

    ``host`` or ``host/path?query``; "" when there is no usable host. The
    scheme, a leading ``www.``, a default-looking trailing slash and the
    fragment are dropped - none of them changes where the link leads - and an
    IP host is written the plain way whatever notation the mail used. The path
    and query keep their case: they are case-sensitive on the server.
    """
    s = (value or "").strip()
    if not s:
        return ""
    if "://" not in s:
        if _OTHER_SCHEME.match(s):
            return ""       # mailto:, tel:, javascript: - not a place on the web
        s = "http://" + s.lstrip("/")
    try:
        parts = urlsplit(s)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    if not host or any(c.isspace() for c in host):
        return ""
    ip = canonical_ip(host)
    if ip:
        host = "[" + ip + "]" if ":" in ip else ip
    else:
        if "." not in host:
            return ""
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            pass
        if host.startswith("www.") and host.count(".") >= 2:
            host = host[4:]
    return host + parts.path.rstrip("/") + ("?" + parts.query if parts.query else "")


def _key_host(key: str) -> str:
    for i, c in enumerate(key):
        if c in "/?":
            return key[:i]
    return key


# --------------------------------------------------------------------------
# the loaded lists
# --------------------------------------------------------------------------

# kind: "url"    - this exact address is listed
#       "host"   - this exact host is listed
#       "domain" - the host's registrable domain is listed
#       "path"   - a DIFFERENT address on this host is listed
Hit = namedtuple("Hit", "kind source entry")


@dataclass
class FeedInfo:
    source: str
    path: str
    entries: int = 0
    fetched: datetime | None = None
    error: str = ""

    def age_days(self, now=None):
        if self.fetched is None:
            return None
        return max(0, ((now or datetime.now(timezone.utc)) - self.fetched).days)

    def stale(self, now=None) -> bool:
        age = self.age_days(now)
        return age is not None and age > STALE_DAYS

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "path": self.path,
            "entries": self.entries,
            "fetched": self.fetched.isoformat(timespec="seconds") if self.fetched else None,
            "age_days": self.age_days(),
            "stale": self.stale(),
            "error": self.error,
        }


class FeedSet:
    """Every loaded list, indexed for lookup. Empty (falsy) when none is loaded."""

    def __init__(self):
        self.hosts = {}       # host -> source that lists the whole host
        self.urls = {}        # host/path?query -> source
        self.url_hosts = {}   # host of a listed address that has a path -> source
        self.meta = []        # one FeedInfo per file read

    def __bool__(self) -> bool:
        return bool(self.hosts or self.urls)

    def __len__(self) -> int:
        return len(self.hosts) + len(self.urls)

    def add(self, entry: str, source: str) -> bool:
        key = url_key(entry)
        if not key:
            return False
        host = _key_host(key)
        if key == host:
            self.hosts.setdefault(host, source)
        else:
            self.urls.setdefault(key, source)
            self.url_hosts.setdefault(host, source)
        return True

    def info(self, source: str):
        return next((m for m in self.meta if m.source == source), None)

    def _host_hit(self, host: str):
        if host in self.hosts:
            return Hit("host", self.hosts[host], host)
        rdom = registered_domain(host)
        if rdom and rdom != host and rdom in self.hosts:
            return Hit("domain", self.hosts[rdom], rdom)
        return None

    def lookup(self, url: str):
        """The strongest way this address is listed, or ``None``."""
        key = url_key(url)
        if not key:
            return None
        host = _key_host(key)
        if key != host and key in self.urls:
            return Hit("url", self.urls[key], key)
        hit = self._host_hit(host)
        if hit is None and host in self.url_hosts:
            hit = Hit("path", self.url_hosts[host], host)
        return hit

    def lookup_host(self, host: str):
        """For a bare domain (the sender's): listed as a host or a domain."""
        key = url_key(host)
        return self._host_hit(_key_host(key)) if key else None


# --------------------------------------------------------------------------
# reading (local, no network)
# --------------------------------------------------------------------------

def default_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "phishingtool" / "feeds"


def resolve_dir(feeds_dir=None) -> Path:
    """Where the lists live: argument > PHISHINGTOOL_FEEDS > per-user cache."""
    if feeds_dir:
        return Path(feeds_dir)
    env = os.environ.get(_ENV, "").strip()
    return Path(env) if env else default_dir()


def _parse_time(value: str):
    try:
        when = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _read(path: Path, feeds: FeedSet) -> FeedInfo:
    info = FeedInfo(source=path.stem.lower(), path=str(path))
    # utf-8-sig: a list typed in Notepad starts with a BOM.
    with path.open(encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                name, _, value = line[1:].partition(":")
                name, value = name.strip().lower(), value.strip()
                if name == "source" and value:
                    info.source = value.lower()
                elif name == "fetched":
                    info.fetched = _parse_time(value)
                continue
            if feeds.add(line, info.source):
                info.entries += 1
    if info.fetched is None:
        # A hand-written list has no header; its date is the file's own.
        info.fetched = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    return info


def load(feeds_dir=None) -> FeedSet:
    """Read every ``*.txt`` in the feeds folder. No folder = an empty set."""
    feeds = FeedSet()
    folder = resolve_dir(feeds_dir)
    if not folder.is_dir():
        return feeds
    for path in sorted(folder.glob("*.txt")):
        try:
            feeds.meta.append(_read(path, feeds))
        except OSError as exc:
            # Not silently: `feeds status` shows the file that could not be read.
            feeds.meta.append(FeedInfo(source=path.stem.lower(), path=str(path),
                                       error=type(exc).__name__ + ": " + str(exc)))
    return feeds


# --------------------------------------------------------------------------
# parsing what the sources send (pure functions)
# --------------------------------------------------------------------------

def _data_lines(text: str) -> list:
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def parse_url_lines(text: str) -> list:
    """One URL per line (OpenPhish).

    A list address that has moved usually answers 200 with an HTML page, so
    "most lines are URLs" is checked before anything is written: an error page
    must not replace yesterday's good list.
    """
    lines = _data_lines(text)
    urls = [line for line in lines if line.lower().startswith(_HTTP)]
    if not urls or len(urls) * 2 < len(lines):
        raise FeedError("liste yerine baska bir icerik geldi (" + str(len(urls))
                        + "/" + str(len(lines)) + " satir URL)")
    return urls


def parse_urlhaus_csv(text: str) -> list:
    """URLhaus CSV export: ``id,dateadded,url,url_status,...,urlhaus_link,...``.

    The first http(s) field of a row is the listed URL; the later one is the
    link to URLhaus's own report page and is not an indicator.
    """
    urls = []
    for row in csv.reader(_data_lines(text)):
        for field in row:
            if field.strip().lower().startswith(_HTTP):
                urls.append(field.strip())
                break
    if not urls:
        raise FeedError("URLhaus yanitinda URL yok")
    return urls


def parse_usom(payload) -> tuple:
    """One page of the USOM address API -> (entries, page count)."""
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        raise FeedError("USOM yaniti beklenen bicimde degil")
    entries = [str(m.get("url") or "").strip()
               for m in payload["models"] if isinstance(m, dict)]
    try:
        pages = int(payload.get("pageCount") or 1)
    except (TypeError, ValueError):
        pages = 1
    return [e for e in entries if e], pages


# --------------------------------------------------------------------------
# downloading (the only network code)
# --------------------------------------------------------------------------

def _http_get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise FeedError("yalniz https adresleri indirilir")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise FeedError("yanit boyut sinirini asiyor (" + str(MAX_BYTES) + " bayt)")
    return data


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _fetch_openphish(days, now) -> list:
    return parse_url_lines(_text(_http_get(OPENPHISH_URL)))


def _fetch_usom(days, now) -> list:
    since = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    entries, page, pages = [], 1, 1
    while page <= min(pages, USOM_MAX_PAGES):
        data = _http_get(USOM_URL + "?per-page=" + str(USOM_PAGE_SIZE)
                         + "&date_gte=" + since + "&page=" + str(page))
        try:
            payload = json.loads(_text(data))
        except ValueError:
            raise FeedError("USOM yaniti JSON degil") from None
        got, pages = parse_usom(payload)
        if not got:
            break
        entries += got
        page += 1
    return entries


def _fetch_urlhaus(days, now) -> list:
    key = os.environ.get(URLHAUS_KEY_ENV, "").strip()
    if not key:
        raise FeedSkipped(URLHAUS_KEY_ENV + " tanimli degil "
                          "(ucretsiz anahtar: https://auth.abuse.ch/)")
    if not _AUTH_KEY.fullmatch(key):
        raise FeedError(URLHAUS_KEY_ENV + " gecersiz karakter iceriyor")
    return parse_urlhaus_csv(_text(_http_get(URLHAUS_URL.format(key=key))))


_FETCHERS = {
    "openphish": _fetch_openphish,
    "usom": _fetch_usom,
    "urlhaus": _fetch_urlhaus,
}


@dataclass
class UpdateResult:
    source: str
    status: str          # ok | skipped | failed
    entries: int = 0
    message: str = ""

    def to_dict(self) -> dict:
        return {"source": self.source, "status": self.status,
                "entries": self.entries, "message": self.message}


def _write(path: Path, source: str, entries: list, now: datetime) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    head = [
        "# phishingtool tehdit listesi - `phishingtool feeds update` bu dosyayi yeniden yazar",
        "# source: " + source,
        "# fetched: " + now.isoformat(timespec="seconds"),
        "# entries: " + str(len(entries)),
    ]
    # Write beside the target and swap: an interrupted download leaves the old
    # list in place instead of half a new one.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(head + entries) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _describe(exc) -> str:
    """Error text for the terminal - never with the Auth-Key in it."""
    text = type(exc).__name__ + ": " + " ".join(str(exc).split())
    key = os.environ.get(URLHAUS_KEY_ENV, "").strip()
    return text.replace(key, "***") if key else text


def update(sources=None, feeds_dir=None, days=USOM_DAYS, now=None) -> list:
    """Download the named sources (default: all) into the feeds folder.

    One source failing does not stop the others, and a failed or empty
    download never overwrites the list already on disk.
    """
    folder = resolve_dir(feeds_dir)
    now = now or datetime.now(timezone.utc)
    results = []
    for source in (sources or SOURCES):
        fetch = _FETCHERS.get(source)
        if fetch is None:
            results.append(UpdateResult(source, "failed", 0, "bilinmeyen kaynak"))
            continue
        try:
            entries = sorted({key for key in map(url_key, fetch(days, now)) if key})
            if not entries:
                raise FeedError("liste bos geldi")
            _write(folder / (source + ".txt"), source, entries, now)
            results.append(UpdateResult(source, "ok", len(entries)))
        except FeedSkipped as exc:
            results.append(UpdateResult(source, "skipped", 0, str(exc)))
        except (FeedError, OSError, ValueError) as exc:
            # OSError covers URLError/HTTPError/timeouts and an unwritable folder.
            results.append(UpdateResult(source, "failed", 0, _describe(exc)))
    return results
