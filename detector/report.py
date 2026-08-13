"""Render a Result as human-readable text (rich if available) or JSON."""
from __future__ import annotations
import json

from . import mitre
from .iocs import defang

_COLORS = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
_IOC_TITLES = (("urls", "URL"), ("domains", "Domain"), ("ips", "IP"),
               ("emails", "E-posta"))


def to_json(result, source=None, iocs=None) -> str:
    d = result.to_dict()
    if source:
        d = {"source": source, **d}
    if iocs is not None:
        d["iocs"] = iocs.to_dict()
    return json.dumps(d, ensure_ascii=False, indent=2)


def iocs_lines(iocs) -> list:
    """IOC block, defanged — JSON/CSV output carries the raw values instead."""
    if iocs is None:
        return []
    lines = ["IOC listesi (defanged — tıklanamaz; ham değerler için --json):"]
    d = iocs.to_dict()
    for key, title in _IOC_TITLES:
        vals = d.get(key) or []
        if not vals:
            continue
        lines.append("  " + title + " (" + str(len(vals)) + "):")
        lines += ["    " + defang(v) for v in vals]
    if iocs.attachments:
        lines.append("  Ek (" + str(len(iocs.attachments)) + "):")
        for a in iocs.attachments:
            lines.append("    " + (a["filename"] or "(isimsiz)") + "  ·  " +
                         str(a["size"]) + " B  ·  " + (a["content_type"] or "?"))
            lines.append("      sha256=" + (a["sha256"] or "(boş ek)"))
    if len(lines) == 1:
        lines.append("  IOC bulunamadı.")
    return lines


def print_iocs(iocs):
    """Plain print on purpose: this block is meant to be copied out verbatim."""
    print("")
    print("\n".join(iocs_lines(iocs)))


_REASON_TR = {
    "allowlist": "gönderen doğrulanmış + allowlist'te, sert iz yok",
    "hard_critical": "sert toplam ≥ 45",
    "hard_high": "sert toplam ≥ 22",
    "hard_medium": "sert toplam ≥ 10",
    "soft_pileup": "sert iz var, yumuşak yığılmayla toplam ≥ 30",
    "weak_hard_evidence": "sert toplam < 10, yumuşak yığılma da yok",
    "no_hard_evidence": "sert iz yok — yalnız yumuşak sinyal",
}


def _num(x) -> str:
    """Trim a float to at most one decimal: 5.0 -> '5', 5.42 -> '5.4'."""
    x = round(float(x), 1)
    return str(int(x)) if x == int(x) else str(x)


def breakdown_lines(result) -> list:
    """Two Turkish lines: how the score adds up, and which rule set the verdict."""
    b = getattr(result, "breakdown", None)
    if b is None:
        return []
    soft = "yumuşak " + _num(b.soft_raw)
    if b.soft_raw and b.multiplier != 1.0:
        soft += "×" + _num(b.multiplier) + "=" + _num(b.soft)
    total = str(result.score) + "/" + str(result.max_score)
    if b.capped:
        total += " (üst sınır)"
    reason = _REASON_TR.get(b.reason, b.reason)
    if not b.hard_count and not b.soft_count:
        reason = "hiç gösterge yok"
    return [
        "Skor kırılımı: sert " + _num(b.hard) + " (" + str(b.hard_count) + " gösterge)"
        " + " + soft + " (" + str(b.soft_count) + " gösterge)  =  " + total,
        "Verdict nedeni: " + reason + " → " + result.verdict +
        "  ·  auth=" + b.auth_level + " (yumuşak çarpan ×" + _num(b.multiplier) + ")" +
        ("  ·  allowlist" if b.trusted else ""),
    ]


def technique_lines(result) -> list:
    """MITRE ATT&CK block: one line per technique, with what raised it.

    Turns tool-private indicator slugs into the vocabulary a SOC already maps
    its detections and playbooks against.
    """
    rows = mitre.summary(result.indicators)
    if not rows:
        return []
    width = max(len(r["id"]) for r in rows)
    lines = ["MITRE ATT&CK teknikleri (" + str(len(rows)) + "):"]
    for r in rows:
        lines.append("  " + r["id"].ljust(width) + "  " + r["name"] +
                     "  —  " + ", ".join(r["indicators"]))
    return lines


def technique_summary_line(result) -> str:
    """Same information as one short line, for space-constrained surfaces."""
    rows = mitre.summary(result.indicators)
    return "ATT&CK: " + " · ".join(r["id"] for r in rows) if rows else ""


def _plain(result, source) -> str:
    lines = []
    if source:
        lines.append("Kaynak: " + source)
    lines.append(_EMOJI.get(result.verdict, "") + " VERDICT: " + result.verdict.upper() +
                 "  (skor " + str(result.score) + "/" + str(result.max_score) + ")")
    a = result.auth
    lines.append("Auth: SPF=" + a["spf"] + " DKIM=" + a["dkim"] + " DMARC=" + a["dmarc"])
    lines += breakdown_lines(result)
    lines.append("")
    if not result.indicators:
        lines.append("Gösterge yok — belirgin phishing işareti bulunamadı.")
    else:
        lines.append(str(len(result.indicators)) + " gösterge:")
        for i in result.indicators:
            lines.append("  [" + i.severity.upper().ljust(8) + "] +" + str(i.weight).rjust(2) +
                         " " + i.id + " (" + i.category + ")" +
                         ("  ·  " + i.technique if i.technique else ""))
            lines.append("        kanıt: " + i.evidence)
            lines.append("        açıklama: " + i.explanation)
        block = technique_lines(result)
        if block:
            lines.append("")
            lines += block
    return "\n".join(lines)


def print_bench(bench, source=None, limit=10):
    """Print benchmark metrics, the threshold sweep and the actual mistakes."""
    print(_bench_plain(bench, source, limit))


def _bench_plain(bench, source=None, limit=10) -> str:
    m = bench.metrics()
    lines = []
    if source:
        lines.append("Korpus: " + str(source))
    lines.append("Etiketli dosya: " + str(len(bench.cases)) +
                 "  ·  esik: verdict >= " + bench.threshold)
    lines.append("")
    lines.append("Karisiklik matrisi (" + bench.threshold + "):")
    lines.append("                 tahmin: phish   tahmin: ham")
    lines.append("  gercek phish   TP=" + str(m.tp).ljust(12) + "FN=" + str(m.fn))
    lines.append("  gercek ham     FP=" + str(m.fp).ljust(12) + "TN=" + str(m.tn))
    lines.append("")
    lines.append("  precision " + _pct(m.precision) + "   (flagladiklarimizin ne kadari gercekten phishing)")
    lines.append("  recall    " + _pct(m.recall) + "   (gercek phishinglerin ne kadarini yakaladik)")
    lines.append("  F1        " + _pct(m.f1))
    lines.append("  accuracy  " + _pct(m.accuracy))
    lines.append("  FP orani  " + _pct(m.false_positive_rate) + "   (mesru mailin ne kadarini bosuna flagladik)")
    lines.append("")
    lines.append("Esik taramasi:")
    lines.append("  esik       precision  recall     F1         FP")
    for t, sm in bench.sweep():
        lines.append("  " + t.ljust(11) + _pct(sm.precision).ljust(11) +
                     _pct(sm.recall).ljust(11) + _pct(sm.f1).ljust(11) + str(sm.fp))

    for kind, title in (("FP", "Yanlis pozitif (mesru ama flaglandi)"),
                        ("FN", "Yanlis negatif (phishing ama kacti)")):
        rows = bench.failures(kind)
        if not rows:
            continue
        lines.append("")
        lines.append(title + " — " + str(len(rows)) + " adet:")
        for c in rows[:limit]:
            lines.append("  " + c.file + "  [" + c.verdict + " " + str(c.score) + "]" +
                         ("  sert: " + ", ".join(c.hard_ids) if c.hard_ids else "  (sert iz yok)"))
        if len(rows) > limit:
            lines.append("  ... +" + str(len(rows) - limit) + " tane daha")

    for label, rows in (("Analiz edilemedi", [c.file + " — " + c.error for c in bench.errors]),
                        ("Etiketli ama dosya yok", bench.missing),
                        ("Etiketsiz .eml", bench.unlabeled)):
        if rows:
            lines.append("")
            lines.append(label + " (" + str(len(rows)) + "): " + ", ".join(rows[:limit]) +
                         (" ..." if len(rows) > limit else ""))
    return "\n".join(lines)


def _pct(x) -> str:
    return format(x * 100, ".1f") + "%"


def bench_to_json(bench, source=None) -> str:
    d = bench.to_dict()
    if source:
        d = {"source": str(source), **d}
    return json.dumps(d, ensure_ascii=False, indent=2)


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
    console.print("[dim]Auth:[/] SPF=" + a["spf"] + " DKIM=" + a["dkim"] + " DMARC=" + a["dmarc"])
    for line in breakdown_lines(result):
        console.print("[dim]" + line + "[/]")
    console.print("")
    if not result.indicators:
        console.print("[green]Gösterge yok — belirgin phishing işareti bulunamadı.[/]")
        return
    t = Table(show_lines=True, expand=False)
    t.add_column("Sev")
    t.add_column("W", justify="right")
    t.add_column("Gösterge")
    t.add_column("ATT&CK")
    t.add_column("Kanıt / Açıklama", overflow="fold")
    for i in result.indicators:
        c = _COLORS.get(i.severity, "white")
        t.add_row("[" + c + "]" + i.severity + "[/]", str(i.weight), i.id,
                  i.technique or "—",
                  i.evidence + "\n[dim]" + i.explanation + "[/]")
    console.print(t)
    for line in technique_lines(result):
        console.print("[dim]" + line + "[/]")
