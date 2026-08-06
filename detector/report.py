"""Render a Result as human-readable text (rich if available) or JSON."""
from __future__ import annotations
import json

_COLORS = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def to_json(result, source=None) -> str:
    d = result.to_dict()
    if source:
        d = {"source": source, **d}
    return json.dumps(d, ensure_ascii=False, indent=2)


def _plain(result, source) -> str:
    lines = []
    if source:
        lines.append("Kaynak: " + source)
    lines.append(_EMOJI.get(result.verdict, "") + " VERDICT: " + result.verdict.upper() +
                 "  (skor " + str(result.score) + "/" + str(result.max_score) + ")")
    a = result.auth
    lines.append("Auth: SPF=" + a["spf"] + " DKIM=" + a["dkim"] + " DMARC=" + a["dmarc"])
    lines.append("")
    if not result.indicators:
        lines.append("Gösterge yok — belirgin phishing işareti bulunamadı.")
    else:
        lines.append(str(len(result.indicators)) + " gösterge:")
        for i in result.indicators:
            lines.append("  [" + i.severity.upper().ljust(8) + "] +" + str(i.weight).rjust(2) +
                         " " + i.id + " (" + i.category + ")")
            lines.append("        kanıt: " + i.evidence)
            lines.append("        açıklama: " + i.explanation)
    return "\n".join(lines)


def print_report(result, source=None):
    """Pretty-print with rich; fall back to plain text if rich is missing."""
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        print(_plain(result, source))
        return

    console = Console()
    color = _COLORS.get(result.verdict, "white")
    if source:
        console.print("[dim]Kaynak:[/] " + source)
    console.print("[" + color + "]" + _EMOJI.get(result.verdict, "") + " " +
                  result.verdict.upper() + " — skor " + str(result.score) + "/" +
                  str(result.max_score) + "[/]")
    a = result.auth
    console.print("[dim]Auth:[/] SPF=" + a["spf"] + " DKIM=" + a["dkim"] + " DMARC=" + a["dmarc"] + "\n")
    if not result.indicators:
        console.print("[green]Gösterge yok — belirgin phishing işareti bulunamadı.[/]")
        return
    t = Table(show_lines=True, expand=False)
    t.add_column("Sev")
    t.add_column("W", justify="right")
    t.add_column("Gösterge")
    t.add_column("Kanıt / Açıklama", overflow="fold")
    for i in result.indicators:
        c = _COLORS.get(i.severity, "white")
        t.add_row("[" + c + "]" + i.severity + "[/]", str(i.weight), i.id,
                  i.evidence + "\n[dim]" + i.explanation + "[/]")
    console.print(t)
