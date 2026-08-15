"""Command-line entrypoint.

  phishingtool analyze <file.eml|.msg|->  [--online] [--json] [--iocs] [--hops]
                                          [--html DOSYA]
  phishingtool batch   <dir>              [--online] [--json] [--iocs] [--verbose]
  phishingtool bench   <corpus dir>       [--threshold high] [--json]

Installed as the `phishingtool` console script; `python -m detector.cli ...`
works identically from a source checkout.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
import traceback
from pathlib import Path

from . import (analyzer, bench as _bench, html_report as _html, iocs as _iocs,
               parser as _parser, received as _received, report)

# Windows legacy consoles default to a regional codepage (e.g. cp1254) that
# cannot encode emoji / some characters. Force UTF-8 so output never crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def cmd_analyze(args) -> int:
    ctx = analyzer.build_context(args.data_dir)
    src = args.input
    # Parse first: --iocs needs the ParsedEmail, not just the score.
    if src == "-":
        # Read stdin as bytes: a piped .msg is binary, and even for .eml this
        # avoids the console codepage rewriting the mail before we parse it.
        raw = (sys.stdin.buffer.read() if hasattr(sys.stdin, "buffer")
               else sys.stdin.read().encode("utf-8", "replace"))
        email = _parser.parse_bytes(raw)
        src = "(stdin)"
    else:
        p = Path(src)
        if not p.exists():
            print("HATA: dosya yok: " + src, file=sys.stderr)
            return 2
        email = _parser.parse_file(p)
    result = analyzer.analyze(email, online=args.online, ctx=ctx)
    found = _iocs.collect(email) if args.iocs else None
    # None (flag off) and [] (asked, mail has no chain) mean different things.
    hops = _received.parse(email) if args.hops else None
    if args.html:
        try:
            Path(args.html).write_text(
                _html.to_html(result, source=src, iocs=found, email=email,
                              hops=hops),
                encoding="utf-8")
        except OSError as exc:
            print("HATA: HTML yazilamadi: " + str(exc), file=sys.stderr)
            return 2
        # stderr, so `--json --html` keeps stdout valid JSON.
        print("HTML rapor yazildi: " + args.html, file=sys.stderr)
    if args.json:
        print(report.to_json(result, source=src, iocs=found, hops=hops))
    else:
        report.print_report(result, source=src, hops=hops)
        if found is not None:
            report.print_iocs(found)
    return 0


def cmd_batch(args) -> int:
    ctx = analyzer.build_context(args.data_dir)
    d = Path(args.dir)
    if not d.is_dir():
        print("HATA: klasor yok: " + args.dir, file=sys.stderr)
        return 2
    rows = []
    failed = 0
    for f in sorted(p for g in _parser.MAIL_GLOBS for p in d.glob(g)):
        try:
            email = _parser.parse_file(f)
            rows.append((f.name, analyzer.analyze(email, online=args.online, ctx=ctx),
                         _iocs.collect(email) if args.iocs else None, ""))
        except Exception as exc:
            # Never swallow the reason. An unexplained "error" row means a mail
            # quietly left the scan - a false negative nobody can see. The
            # message goes to stderr so stdout stays valid CSV/JSON.
            failed += 1
            err = _describe(exc)
            print("HATA: " + f.name + ": " + err, file=sys.stderr)
            if args.verbose:
                traceback.print_exc()
            rows.append((f.name, None, None, err))
    if args.json:
        out = []
        for name, r, found, err in rows:
            row = dict({"source": name}, **(r.to_dict() if r else {"error": err}))
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
        head.append("error")   # empty on success, "Type: message" on failure
        w.writerow(head)
        for name, r, found, err in rows:
            row = ([name, r.verdict, r.score, r.auth["spf"], r.auth["dkim"],
                    r.auth["dmarc"], ";".join(i.id for i in r.indicators)]
                   if r else [name, "error", "", "", "", "", ""])
            if args.iocs:
                row += _ioc_columns(found)
            row.append(err)
            w.writerow(row)
    # A run that could not read part of its input must not look successful.
    return 1 if failed else 0


def _describe(exc) -> str:
    """One-line "Type: message" label for an error row (message may be empty)."""
    text = " ".join(str(exc).split())
    return type(exc).__name__ + (": " + text if text else "")


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
                            ctx=analyzer.build_context(args.data_dir))
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
        prog="phishingtool",
        description="Phishing e-posta tespit/analiz araci (savunma, statik, offline-first).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # Shared by every subcommand: where the dictionaries are read from.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-dir",
                        help="Sozluk klasoru (varsayilan: paket ici detector/data; "
                             "PHISHINGTOOL_DATA ortam degiskeni de gecerli)")

    a = sub.add_parser("analyze", parents=[common],
                       help="Tek bir .eml/.msg dosyasini veya stdin'i analiz et")
    a.add_argument("input", help=".eml veya .msg yolu, ya da '-' (stdin ham e-posta)")
    a.add_argument("--online", action="store_true",
                   help="DNS/WHOIS/itibar sorgularini etkinlestir (ag kullanir)")
    a.add_argument("--json", action="store_true", help="JSON cikti")
    a.add_argument("--iocs", action="store_true",
                   help="IOC listesi ekle: URL/domain/IP/e-posta/ek SHA256 "
                        "(metinde defanged, --json ile ham)")
    a.add_argument("--hops", action="store_true",
                   help="Received zincirini hop hop goster: zaman/gecikme, "
                        "kimden-kime, TLS, ters ad uyusmazligi (ag kullanmaz)")
    a.add_argument("--html", metavar="DOSYA",
                   help="Raporu tek dosyalik HTML olarak yaz (gomulu CSS; JS ve "
                        "dis kaynak yok, mail icerigi tiklanamaz)")
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("batch", parents=[common],
                       help="Bir klasordeki tum .eml/.msg dosyalarini tara")
    b.add_argument("dir", help="Klasor yolu")
    b.add_argument("--online", action="store_true")
    b.add_argument("--json", action="store_true")
    b.add_argument("--iocs", action="store_true",
                   help="Her satira IOC kolonlari ekle (urls/domains/ips/sha256, ham)")
    b.add_argument("-v", "--verbose", action="store_true",
                   help="Analiz edilemeyen dosyalar icin tam traceback yaz (stderr). "
                        "Hata sebebi zaten 'error' kolonunda ve stderr'de.")
    b.set_defaults(func=cmd_batch)

    n = sub.add_parser(
        "bench", parents=[common],
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
