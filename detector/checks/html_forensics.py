"""Tier 2 - static forensics on the HTML body.

Looks for phishing tradecraft that lives in the markup itself: login forms
that POST off-domain, password inputs embedded in the mail, meta-refresh
redirects, <base> href tricks, hidden iframes, obfuscated inline JavaScript,
and text hidden from the reader (used to poison spam filters).

Pure stdlib. Never fetches, never executes - just parses the string.
"""
from __future__ import annotations
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from ..indicators import Indicator
from ..util import registered_domain

_HIDDEN_STYLE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0"
    r"|opacity\s*:\s*0|height\s*:\s*0|width\s*:\s*0)",
    re.IGNORECASE,
)
_JS_OBFUSCATION = re.compile(
    r"(eval\s*\(|unescape\s*\(|atob\s*\(|fromCharCode|document\.write"
    r"|String\.fromCharCode|\\x[0-9a-f]{2}|%[0-9a-f]{2}){2,}",
    re.IGNORECASE,
)
_META_URL = re.compile(r"url\s*=\s*([^;'\"]+)", re.IGNORECASE)


def _host(url: str) -> str:
    try:
        return (urlparse(url.strip()).hostname or "").lower()
    except Exception:
        return ""


class _Scan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.form_actions = []      # list of action URLs
        self.has_password = False
        self.iframes = []           # list of (src, hidden)
        self.base_href = None
        self.meta_refresh = None    # target url
        self.scripts = []           # inline script bodies
        self.hidden_chars = 0
        self._hidden_stack = []     # tags currently hiding content
        self._in_script = False
        self._script_buf = []

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        a = {k.lower(): (v or "") for k, v in attrs}
        style = a.get("style", "")
        hidden = bool(_HIDDEN_STYLE.search(style))

        if t == "form":
            self.form_actions.append(a.get("action", ""))
        elif t == "input" and a.get("type", "").lower() == "password":
            self.has_password = True
        elif t == "iframe":
            self.iframes.append((a.get("src", ""), hidden))
        elif t == "base" and a.get("href"):
            self.base_href = a["href"]
        elif t == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = _META_URL.search(a.get("content", ""))
            if m:
                self.meta_refresh = m.group(1).strip()
        elif t == "script":
            self._in_script = True
            self._script_buf = []

        # Track hidden containers so we can measure concealed text.
        if hidden and t not in ("br", "img", "input", "meta", "base"):
            self._hidden_stack.append(t)

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == "script" and self._in_script:
            self._in_script = False
            self.scripts.append("".join(self._script_buf))
        if self._hidden_stack and self._hidden_stack[-1] == t:
            self._hidden_stack.pop()

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)
            return
        if self._hidden_stack:
            self.hidden_chars += len(data.strip())


def run(email, online=False, ctx=None):
    html = email.html_body or ""
    if not html.strip():
        return []

    s = _Scan()
    try:
        s.feed(html)
    except Exception:
        pass

    out = []
    from_rdom = registered_domain(email.from_domain)

    for action in s.form_actions:
        if not action:
            continue
        host = _host(action)
        if not host:
            continue  # relative/mailto - not an off-domain POST
        adom = registered_domain(host)
        if adom and from_rdom and adom != from_rdom:
            out.append(Indicator("form_external_action", "html", "high", 18,
                "Form verisi disari gonderiliyor: " + host,
                "E-postadaki form, gonderenin domaininden farkli bir sunucuya POST ediyor - veri hirsizligi."))
            break

    if s.has_password:
        out.append(Indicator("html_password_input", "html", "high", 16,
            "E-posta govdesinde parola giris alani (<input type=password>) var",
            "Mesru kurumlar sifreyi e-posta icindeki formla istemez."))

    if s.meta_refresh and _host(s.meta_refresh):
        out.append(Indicator("meta_refresh_redirect", "html", "medium", 12,
            "meta-refresh yonlendirme: " + s.meta_refresh,
            "Sayfa acildigi an baska adrese otomatik yonlendirir."))

    if any(hidden or (src and _host(src) and registered_domain(_host(src)) != from_rdom)
           for src, hidden in s.iframes):
        out.append(Indicator("hidden_iframe", "html", "medium", 12,
            "Gizli veya harici iframe tespit edildi",
            "Gizli iframe arka planda icerik/istek yukleyebilir."))

    if s.base_href:
        out.append(Indicator("base_tag_href", "html", "medium", 10,
            "<base> etiketi tum baglantilari yeniden koklendiriyor: " + s.base_href,
            "Gorunen goreli linkler <base> ile baska sunucuya yonlenir."))

    for body in s.scripts:
        if _JS_OBFUSCATION.search(body):
            out.append(Indicator("obfuscated_script", "html", "medium", 12,
                "Govdede sifrelenmis/gizlenmis inline JavaScript",
                "eval/atob/fromCharCode gibi teknikler kotu niyetli kodu gizler."))
            break

    if s.hidden_chars >= 200:
        out.append(Indicator("hidden_text", "html", "low", 8,
            "Gizlenmis metin (~" + str(s.hidden_chars) + " karakter, display:none/0px)",
            "Gorunmez metin spam filtrelerini yanultmak icin kullanilir."))

    return out
