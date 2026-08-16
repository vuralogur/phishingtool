"""Render a Result as human-readable text (rich if available) or JSON."""
from __future__ import annotations
import json

from . import mitre
from . import received as _received
from .iocs import defang

_COLORS = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
_IOC_TITLES = (("urls", "URL"), ("domains", "Domain"), ("ips", "IP"),
               ("emails", "E-posta"))


def to_json(result, source=None, iocs=None, hops=None) -> str:
    d = result.to_dict()
    if source:
        d = {"source": source, **d}
    if iocs is not None:
        d["iocs"] = iocs.to_dict()
    if hops is not None:
        d["received"] = [h.to_dict() for h in hops]
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


_CONFIG_TR = {
    "weights": "ağırlıklar",
    "thresholds": "eşikler",
    "soft_multiplier": "yumuşak çarpan",
    "soft_ids": "yumuşak gösterge listesi",
}


def breakdown_lines(result) -> list:
    """Two Turkish lines: how the score adds up, and which rule set the verdict.

    A third line appears only when an override file was in play - the numbers
    above are then not the built-in model's, and a reader who cannot see that
    cannot reproduce the score.
    """
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
    lines = [
        "Skor kırılımı: sert " + _num(b.hard) + " (" + str(b.hard_count) + " gösterge)"
        " + " + soft + " (" + str(b.soft_count) + " gösterge)  =  " + total,
        "Verdict nedeni: " + reason + " → " + result.verdict +
        "  ·  auth=" + b.auth_level + " (yumuşak çarpan ×" + _num(b.multiplier) + ")" +
        ("  ·  allowlist" if b.trusted else ""),
    ]
    source = getattr(b, "config_source", "")
    if source:
        changed = [_CONFIG_TR.get(c, c) for c in getattr(b, "config_changed", ())]
        lines.append("Ayar dosyası: " + source + "  ·  değişen: " +
                     (", ".join(changed) if changed else
                      "yok (dosya varsayılanlarla aynı)"))
    return lines


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


_HOP_FLAG_TR = {
    "private_ip": "köken IP özel/ayrılmış aralıkta — internetten gelmiş görünmüyor",
    "rdns_mismatch": "duyurulan ad, alıcı sunucunun yazdığı ters ad ile uyuşmuyor",
    "no_tls": "şifresiz teslim (TLS yok)",
    "big_delay": "önceki hoptan sonra uzun bekleme",
    "clock_skew": "zaman damgası bir öncekinden eski — saatler tutarsız",
    "unparsed": "satır çözümlenemedi, ham hâliyle veriliyor",
}
HOP_TRUST_NOTE = ("Not: yalnızca güvendiğiniz ilk sunucunun üstündeki hoplar "
                  "güvenilirdir — alt hoplar gönderen tarafından uydurulmuş "
                  "olabilir.")


def _duration(seconds) -> str:
    s = abs(int(seconds))
    if s < 60:
        return str(s) + " sn"
    if s < 3600:
        return str(s // 60) + " dk"
    return str(s // 3600) + " sa"


def _delay_tr(seconds) -> str:
    if seconds is None:
        return ""
    return "(" + ("-" if seconds < 0 else "+") + _duration(seconds) + ")"


def _clock(stamp) -> str:
    if stamp is None:
        return "(zaman damgası yok)"
    offset = stamp.strftime("%z")
    return stamp.strftime("%Y-%m-%d %H:%M:%S") + (" " + offset if offset else "")


def hop_flag_text(flag) -> str:
    """Turkish sentence for one hop flag — shared by every surface."""
    return _HOP_FLAG_TR.get(flag, flag)


def hop_time_text(hop) -> str:
    return _clock(hop.time)


def hop_delay_text(hop) -> str:
    """'+5 sn' / '-2 dk', or empty when the gap could not be computed."""
    return _delay_tr(hop.delay).strip("()")


def _hop_sender(hop) -> str:
    out = hop.from_host or "(ad yok)"
    if hop.from_rdns:
        out += "  ·  ters ad: " + hop.from_rdns
    if hop.from_ip:
        out += "  ·  " + hop.from_ip
    return out


def _hop_target(hop) -> str:
    out = hop.by_host or "(ad yok)"
    if hop.protocol:
        out += "  ·  " + hop.protocol + (" (TLS)" if hop.tls else "")
    return out


def received_lines(hops) -> list:
    """The route the mail took, oldest hop first — evidence, not proof.

    ``None`` means the caller did not ask for the chain; an empty list means it
    asked and the mail carries none, which is itself worth saying out loud.
    """
    if hops is None:
        return []
    if not hops:
        return ["Received zinciri: başlıkta hiç Received satırı yok."]
    lines = ["Received zinciri — " + str(len(hops)) + " hop (en eski önce):"]
    for hop in hops:
        delay = _delay_tr(hop.delay)
        lines.append("  " + str(hop.index) + ". " + _clock(hop.time) +
                     ("  " + delay if delay else ""))
        lines.append("     kimden: " + _hop_sender(hop))
        lines.append("     kime  : " + _hop_target(hop))
        for flag in hop.flags:
            lines.append("     ! " + _HOP_FLAG_TR.get(flag, flag))
        if "unparsed" in hop.flags:
            lines.append("       " + hop.raw)
    lines.append("  " + HOP_TRUST_NOTE)
    return lines


def received_summary_line(hops) -> str:
    """Same chain as one short line, for space-constrained surfaces."""
    if not hops:
        return ""
    s = _received.summary(hops)
    parts = ["Received: " + str(s["count"]) + " hop"]
    if s["origin_ip"]:
        parts.append("köken " + s["origin_ip"])
    if s["span"]:
        parts.append("süre " + _duration(s["span"]))
    if s["flags"]:
        parts.append(str(len(s["flags"])) + " uyarı: " + ", ".join(s["flags"]))
    return "  ·  ".join(parts)


def _plain(result, source, hops=None) -> str:
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
    chain = received_lines(hops)
    if chain:
        lines.append("")
        lines += chain
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


def _received_rich(console, table_cls, hops):
    """Received chain as a rich table (same content as received_lines)."""
    if hops is None:
        return
    console.print("")
    if not hops:
        console.print("[dim]Received zinciri: başlıkta hiç Received satırı yok.[/]")
        return
    t = table_cls(title="Received zinciri — " + str(len(hops)) + " hop (en eski önce)",
                  show_lines=True, expand=False)
    t.add_column("#", justify="right")
    t.add_column("Zaman")
    t.add_column("Δ", justify="right")
    t.add_column("Kimden", overflow="fold")
    t.add_column("Kime", overflow="fold")
    t.add_column("Uyarı", overflow="fold")
    for hop in hops:
        notes = "\n".join(_HOP_FLAG_TR.get(f, f) for f in hop.flags)
        t.add_row(str(hop.index), _clock(hop.time), _delay_tr(hop.delay).strip("()"),
                  _hop_sender(hop), _hop_target(hop),
                  "[yellow]" + notes + "[/]" if notes else "")
    console.print(t)
    console.print("[dim]" + HOP_TRUST_NOTE + "[/]")


def print_report(result, source=None, hops=None):
    """Pretty-print with rich; fall back to plain text if rich is missing."""
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        print(_plain(result, source, hops))
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
        _received_rich(console, Table, hops)
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
    _received_rich(console, Table, hops)
