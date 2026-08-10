"""Command-line entrypoint.

  python -m detector.cli analyze <file.eml | ->  [--online] [--json] [--iocs]
  python -m detector.cli batch   <dir>           [--online] [--json] [--iocs]
  python -m detector.cli bench   <corpus dir>    [--threshold high] [--json]
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path

from . import analyzer, bench as _bench, iocs as _iocs, parser as _parser, report

# Windows legacy consoles default to a regional codepage (e.g. cp1254) that
# cannot encode emoji / some characters. Force UTF-8 so output never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def cmd_analyze(args) -> int:
    ctx = analyzer.build_context()
    src = args.input
    # Parse first: --iocs needs the ParsedEmail, not just the score.
    if src == "-":
        email = _parser.parse_text(sys.stdin.read())
        src = "(stdin)"
    else:
        p = Path(src)
        if not p.exists():
            print("HATA: dosya yok: " + src, file=sys.stderr)
            return 2
        email = _parser.parse_file(p)
    result = analyzer.analyze(email, online=args.online, ctx=ctx)
    found = _iocs.collect(email) if args.iocs else None
    if args.json:
        print(report.to_json(result, source=src, iocs=found))
    else:
        report.print_report(result, source=src)
        if found is not None:
            report.print_iocs(found)
    return 0


def cmd_batch(args) -> int:
    ctx = analyzer.build_context()
    d = Path(args.dir)
    if not d.is_dir():
        print("HATA: klasor yok: " + args.dir, file=sys.stderr)
        return 2
    rows = []
    for f in sorted(d.glob("*.eml")):
        try:
            email = _parser.parse_file(f)
            rows.append((f.name, analyzer.analyze(email, online=args.online, ctx=ctx),
                         _iocs.collect(email) if args.iocs else None))
        except Exception:
            rows.append((f.name, None, None))
    if args.json:
        out = []
        for name, r, found in rows:
            row = dict({"source": name}, **(r.to_dict() if r else {"error": True}))
            if found is not None:
                row["iocs"] = found.to_dict()
            out.append(row)
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        # lineterminator="\n": stdout already translates newlines on Windows, so
        # csv's default "\r\n" would emit a blank line between every row.
        w = csv.writer(sys.stdout, lineterminator="\n")
        head = ["file", "verdict", "score", "spf", "dkim", "dmarc", "indicators"]
        if args.iocs:
            # Raw (not defanged) - a CSV is machine input, feed it to the SIEM.
            head += ["urls", "domains", "ips", "sha256"]
        w.writerow(head)
        for name, r, found in rows:
            row = ([name, r.verdict, r.score, r.auth["spf"], r.auth["dkim"],
                    r.auth["dmarc"], ";".join(i.id for i in r.indicators)]
                   if r else [name, "error", "", "", "", "", ""])
            if args.iocs:
                row += _ioc_columns(found)
            w.writerow(row)
    return 0


def _ioc_columns(found) -> list:
    """The four batch-CSV IOC columns, semicolon-joined (empty on parse error)."""
    if found is None:
        return ["", "", "", ""]
    return [";".join(found.urls), ";".join(found.domains), ";".join(found.ips),
            ";".join(a["sha256"] for a in found.attachments if a["sha256"])]


def cmd_bench(args) -> int:
    """Score the detector against a labelled corpus (precision / recall / F1)."""
    try:
        result = _bench.run(args.dir, labels_path=args.labels,
                            threshold=args.threshold, online=args.online,
                            ctx=analyzer.build_context())
    except _bench.BenchError as exc:
        print("HATA: " + str(exc), file=sys.stderr)
        return 2
    if args.json:
        print(report.bench_to_json(result, source=args.dir))
    else:
        report.print_bench(result, source=args.dir, limit=args.limit)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detector",
        description="Phishing e-posta tespit/analiz araci (savunma, statik, offline-first).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Tek bir .eml dosyasini veya stdin'i analiz et")
    a.add_argument("input", help=".eml yolu veya '-' (stdin ham e-posta)")
    a.add_argument("--online", action="store_true",
                   help="DNS/WHOIS/itibar sorgularini etkinlestir (ag kullanir)")
    a.add_argument("--json", action="store_true", help="JSON cikti")
    a.add_argument("--iocs", action="store_true",
                   help="IOC listesi ekle: URL/domain/IP/e-posta/ek SHA256 "
                        "(metinde defanged, --json ile ham)")
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("batch", help="Bir klasordeki tum .eml dosyalarini tara")
    b.add_argument("dir", help="Klasor yolu")
    b.add_argument("--online", action="store_true")
    b.add_argument("--json", action="store_true")
    b.add_argument("--iocs", action="store_true",
                   help="Her satira IOC kolonlari ekle (urls/domains/ips/sha256, ham)")
    b.set_defaults(func=cmd_batch)

    n = sub.add_parser(
        "bench",
        help="Etiketli korpusa karsi olc: precision / recall / F1 / hata listesi")
    n.add_argument("dir", help="Korpus klasoru (labels.csv veya phish/ ham/ alt klasorleri)")
    n.add_argument("--labels", help="Etiket CSV yolu (varsayilan: <dir>/labels.csv)")
    n.add_argument("--threshold", default="medium",
                   choices=tuple(_bench.VERDICT_RANK),
                   help="Bu verdict ve ustu 'phishing' sayilir (varsayilan: medium)")
    n.add_argument("--limit", type=int, default=10,
                   help="Listelenecek hata ornegi sayisi (varsayilan: 10)")
    n.add_argument("--online", action="store_true")
    n.add_argument("--json", action="store_true")
    n.set_defaults(func=cmd_bench)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
