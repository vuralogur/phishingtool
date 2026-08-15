"""Single-file HTML report: the same verdict, in a form you can send to someone.

Design constraints, all of them security-driven:

* **One file, no dependencies.** CSS is embedded, there is no JavaScript and no
  external resource of any kind, so opening the report cannot make a request -
  a report about a phishing mail must not itself phone home.
* **Nothing from the mail is ever a link.** Every value that came out of the
  analyzed mail (subject, evidence, IOCs) is escaped text; the only clickable
  hrefs in the page point at attack.mitre.org, whose URLs this tool builds
  itself. An analyst opening the report must not be one click away from the
  credential-harvest page they are investigating.
* **IOCs stay defanged**, exactly like the terminal block - the raw values are
  what ``--json`` is for.
"""
from __future__ import annotations
from datetime import datetime
from html import escape

from . import mitre
from .report import (HOP_TRUST_NOTE, breakdown_lines, hop_delay_text,
                     hop_flag_text, hop_time_text, iocs_lines)

_BADGE = {"low": "b-low", "medium": "b-medium", "high": "b-high",
          "critical": "b-critical"}
_VERDICT_TR = {"low": "düşük risk", "medium": "orta risk",
               "high": "yüksek risk", "critical": "kritik"}

_CSS = """
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#ffffff; --ink:#1a1d21;
        --muted:#57606a; --line:#e1e4e8; --code:#f6f8fa; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --card:#161b22; --ink:#e6edf3; --muted:#9198a1;
          --line:#30363d; --code:#0d1117; }
}
* { box-sizing: border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--ink);
       font:15px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.card { max-width:1040px; margin:0 auto 20px; background:var(--card);
        border:1px solid var(--line); border-radius:12px; padding:20px 24px; }
h1 { font-size:19px; margin:0 0 4px; }
h2 { font-size:15px; margin:24px 0 8px; text-transform:uppercase;
     letter-spacing:.04em; color:var(--muted); }
.badge { display:inline-block; padding:8px 16px; border-radius:8px; color:#fff;
         font-size:19px; font-weight:700; letter-spacing:.02em; }
.b-low{background:#1a7f37}.b-medium{background:#9a6700}
.b-high{background:#bc4c00}.b-critical{background:#b31d28}
.meta { color:var(--muted); font-size:13px; margin:6px 0 0; word-break:break-all; }
.kv { margin:12px 0 0; font-size:14px; }
.kv div { margin:2px 0; }
table { border-collapse:collapse; width:100%; margin-top:4px; }
th, td { border-bottom:1px solid var(--line); padding:9px 8px; text-align:left;
         vertical-align:top; font-size:14px; }
th { font-size:12px; text-transform:uppercase; letter-spacing:.04em;
     color:var(--muted); border-bottom-width:2px; }
td.w { text-align:right; white-space:nowrap; font-variant-numeric:tabular-nums; }
td.sev { font-weight:700; white-space:nowrap; }
.s-low{color:#1a7f37}.s-medium{color:#9a6700}
.s-high{color:#bc4c00}.s-critical{color:#b31d28}
.slug { font-family:ui-monospace, SFMono-Regular, Consolas, monospace; }
.cat { color:var(--muted); font-size:12px; }
.ev { font-family:ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size:13px; word-break:break-word; }
.ex { color:var(--muted); margin-top:4px; }
a { color:#0969da; }
@media (prefers-color-scheme: dark) { a { color:#4493f8; } }
pre { background:var(--code); border:1px solid var(--line); border-radius:8px;
      padding:12px; overflow-x:auto; font-size:13px; margin:0; }
.note { color:var(--muted); font-size:13px; }
@media print { body{background:#fff;padding:0} .card{border:0} }
"""


def _e(value) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _rows(result) -> str:
    out = []
    for i in result.indicators:
        tech = "—"
        if i.technique:
            tech = ('<a href="' + _e(mitre.url(i.technique)) + '" target="_blank"'
                    ' rel="noopener noreferrer">' + _e(i.technique) + "</a>"
                    '<div class="cat">' + _e(i.technique_name) + "</div>")
        out.append(
            "<tr>"
            '<td class="sev s-' + _e(i.severity) + '">' + _e(i.severity) + "</td>"
            '<td class="w">+' + _e(i.weight) + "</td>"
            '<td><span class="slug">' + _e(i.id) + "</span>"
            '<div class="cat">' + _e(i.category) + "</div></td>"
            "<td>" + tech + "</td>"
            '<td><div class="ev">' + _e(i.evidence) + "</div>"
            '<div class="ex">' + _e(i.explanation) + "</div></td>"
            "</tr>")
    return "\n".join(out)


_SOURCE_TR = {
    ("msg", "rfc822"): "Outlook .msg — kayıtlı internet başlıkları kullanıldı",
    ("msg", "mapi"): "Outlook .msg — internet başlıkları yok, başlıklar MAPI "
                     "alanlarından kuruldu (SPF/DKIM/Received dosyada yok)",
}


def _mail_section(email) -> str:
    """Who/what the mail claims to be - escaped text, never markup, never a link."""
    if email is None:
        return ""
    sender = email.from_addr
    if email.from_display:
        sender = email.from_display + " <" + email.from_addr + ">"
    rows = [("Gönderen", sender), ("Reply-To", email.reply_to),
            ("Return-Path", email.return_path), ("Alıcı", email.to),
            ("Konu", email.subject), ("Tarih", email.date)]
    fmt = _SOURCE_TR.get((getattr(email, "source_format", "eml"),
                          getattr(email, "header_source", "rfc822")))
    if fmt:
        rows.append(("Dosya biçimi", fmt))
    cells = ["<tr><th>" + _e(k) + "</th><td>" + _e(v) + "</td></tr>"
             for k, v in rows if v]
    if not cells:
        return ""
    return ("<h2>E-posta</h2><table><tbody>" + "\n".join(cells) +
            "</tbody></table>")


def _techniques(result) -> str:
    rows = mitre.summary(result.indicators)
    if not rows:
        return ""
    items = []
    for r in rows:
        items.append('<li><a href="' + _e(r["url"]) + '" target="_blank"'
                     ' rel="noopener noreferrer"><span class="slug">' +
                     _e(r["id"]) + "</span></a> " + _e(r["name"]) +
                     ' <span class="cat">— ' + _e(", ".join(r["indicators"])) +
                     "</span></li>")
    return ("<h2>MITRE ATT&amp;CK (" + str(len(rows)) + ")</h2><ul>" +
            "\n".join(items) + "</ul>")


def _received(hops) -> str:
    """The route the mail took. Host names are hostile input: escaped text only."""
    if hops is None:
        return ""
    if not hops:
        return ('<h2>Received zinciri</h2><p class="note">Başlıkta hiç Received '
                "satırı yok.</p>")
    rows = []
    for hop in hops:
        sender = _e(hop.from_host or "(ad yok)")
        if hop.from_rdns:
            sender += '<div class="cat">ters ad: ' + _e(hop.from_rdns) + "</div>"
        if hop.from_ip:
            sender += '<div class="ev">' + _e(hop.from_ip) + "</div>"
        target = _e(hop.by_host or "(ad yok)")
        if hop.protocol:
            target += ('<div class="cat">' + _e(hop.protocol) +
                       (" (TLS)" if hop.tls else "") + "</div>")
        notes = "<br>".join(_e(hop_flag_text(f)) for f in hop.flags)
        if "unparsed" in hop.flags:
            notes += '<div class="ev">' + _e(hop.raw) + "</div>"
        rows.append("<tr>"
                    '<td class="w">' + _e(hop.index) + "</td>"
                    "<td>" + _e(hop_time_text(hop)) + "</td>"
                    '<td class="w">' + _e(hop_delay_text(hop)) + "</td>"
                    "<td>" + sender + "</td>"
                    "<td>" + target + "</td>"
                    '<td class="ex">' + notes + "</td>"
                    "</tr>")
    return ("<h2>Received zinciri (" + str(len(hops)) + " hop, en eski önce)</h2>"
            "<table><thead><tr><th>#</th><th>Zaman</th><th>Δ</th><th>Kimden</th>"
            "<th>Kime</th><th>Uyarı</th></tr></thead><tbody>" +
            "\n".join(rows) + "</tbody></table>"
            '<p class="note">' + _e(HOP_TRUST_NOTE) + "</p>")


def to_html(result, source=None, iocs=None, email=None, when=None, hops=None) -> str:
    """Render one analysis as a self-contained HTML page.

    ``email`` is the ``ParsedEmail``, used only to show what the mail claims to
    be (sender, subject, date) - as escaped text. ``hops`` is the parsed
    Received chain (``received.parse``), shown only when the caller asked for it.
    """
    stamp = (when or datetime.now()).strftime("%Y-%m-%d %H:%M")
    a = result.auth
    verdict = _e(result.verdict.upper()) + " — " + _e(_VERDICT_TR.get(result.verdict, ""))

    parts = [
        "<!DOCTYPE html>",
        '<html lang="tr"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Phishing analizi — " + _e(result.verdict) + "</title>",
        "<style>" + _CSS + "</style></head><body>",
        '<div class="card">',
        "<h1>Phishing e-posta analizi</h1>",
        '<p class="meta">Kaynak: ' + (_e(source) if source else "(belirtilmedi)") +
        " · Üretildi: " + _e(stamp) + "</p>",
        '<p><span class="badge ' + _BADGE.get(result.verdict, "b-low") + '">' +
        verdict + "</span> <strong>" + _e(result.score) + "/" +
        _e(result.max_score) + "</strong></p>",
        '<div class="kv"><div>Auth: SPF=' + _e(a.get("spf")) + " DKIM=" +
        _e(a.get("dkim")) + " DMARC=" + _e(a.get("dmarc")) + "</div>",
    ]
    for line in breakdown_lines(result):
        parts.append('<div class="note">' + _e(line) + "</div>")
    parts.append("</div>")
    parts.append(_mail_section(email))

    if result.indicators:
        parts.append("<h2>Göstergeler (" + str(len(result.indicators)) + ")</h2>")
        parts.append("<table><thead><tr><th>Severity</th><th>Ağırlık</th>"
                     "<th>Gösterge</th><th>ATT&amp;CK</th>"
                     "<th>Kanıt / açıklama</th></tr></thead><tbody>")
        parts.append(_rows(result))
        parts.append("</tbody></table>")
        parts.append(_techniques(result))
    else:
        parts.append('<p class="note">Gösterge yok — belirgin phishing işareti '
                     "bulunamadı.</p>")

    parts.append(_received(hops))

    if iocs is not None:
        parts.append("<h2>IOC</h2>")
        parts.append("<pre>" + _e("\n".join(iocs_lines(iocs))) + "</pre>")

    parts.append("</div>")
    parts.append('<div class="card note">Statik analiz: hiçbir bağlantı veya ek '
                 "açılmadı, çalıştırılmadı, çözümlenmedi. Bu sayfada maile ait "
                 "hiçbir değer tıklanabilir bağlantı değildir; IOC listesi "
                 "defanged verilir (ham değerler için <code>--json</code>). "
                 "Rapor tek dosyadır: gömülü CSS, JavaScript ve dış kaynak yok."
                 "</div>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"
