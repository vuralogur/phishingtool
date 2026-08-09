"""Command-line entrypoint.

  python -m detector.cli analyze <file.eml | ->  [--online] [--json]
  python -m detector.cli batch   <dir>           [--online] [--json]
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path

from . import analyzer, bench as _bench, report

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
    if src == "-":
        result = analyzer.analyze_text(sys.stdin.read(), online=args.online, ctx=ctx)
        src = "(stdin)"
    else:
        p = Path(src)
        if not p.exists():
            print("HATA: dosya yok: " + src, file=sys.stderr)
            return 2
        result = analyzer.analyze_file(p, online=args.online, ctx=ctx)
    if args.json:
        print(report.to_json(result, source=src))
    else:
        report.print_report(result, source=src)
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
            rows.append((f.name, analyzer.analyze_file(f, online=args.online, ctx=ctx)))
        except Exception:
            rows.append((f.name, None))
    if args.json:
        out = [dict({"source": name}, **(r.to_dict() if r else {"error": True}))
               for name, r in rows]
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        w = csv.writer(sys.stdout)
        w.writerow(["file", "verdict", "score", "spf", "dkim", "dmarc", "indicators"])
        for name, r in rows:
            if r:
                w.writerow([name, r.verdict, r.score, r.auth["spf"], r.auth["dkim"],
                            r.auth["dmarc"], ";".join(i.id for i in r.indicators)])
            else:
                w.writerow([name, "error", "", "", "", "", ""])
    return 0


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
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("batch", help="Bir klasordeki tum .eml dosyalarini tara")
    b.add_argument("dir", help="Klasor yolu")
    b.add_argument("--online", action="store_true")
    b.add_argument("--json", action="store_true")
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
