"""Benchmark harness: measure detection quality against a labelled corpus.

Without numbers, a tuning change is a guess. This module runs the analyzer over
a folder of labelled .eml files and reports precision / recall / F1 plus the
concrete false positives and false negatives, so a scoring change can be judged
as an improvement or a regression instead of being argued about.

Labels come from either
  * a CSV  ``file,label``  (label: phish|ham, plus common synonyms), or
  * ``phish/`` and ``ham/`` subfolders (no CSV needed).

A prediction is "phish" when the verdict reaches ``threshold`` (default
``medium``). The threshold sweep shows what the other cut-offs would have
scored on the same run, which is the cheapest way to pick one.
"""
from __future__ import annotations
import csv
from dataclasses import dataclass, field
from pathlib import Path

from . import analyzer
from .scoring import SOFT_IDS

# Verdict ordering used to turn a verdict into a binary phish/ham prediction.
VERDICT_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
THRESHOLDS = ("medium", "high", "critical")

PHISH = "phish"
HAM = "ham"

# Label spellings people actually type in a corpus CSV.
_LABEL_ALIASES = {
    PHISH: PHISH, "phishing": PHISH, "spam": PHISH, "malicious": PHISH,
    "bad": PHISH, "1": PHISH, "true": PHISH, "kotu": PHISH, "zararli": PHISH,
    HAM: HAM, "benign": HAM, "legit": HAM, "legitimate": HAM, "clean": HAM,
    "good": HAM, "0": HAM, "false": HAM, "iyi": HAM, "temiz": HAM,
}


class BenchError(Exception):
    """Corpus/labels problem that stops the run before any analysis."""


def normalize_label(raw: str) -> str:
    """Map a corpus label spelling onto phish/ham; '' if unrecognised."""
    return _LABEL_ALIASES.get(str(raw).strip().lower(), "")


@dataclass
class Case:
    """One corpus file: what it is, what the analyzer said about it."""
    file: str
    label: str          # phish | ham (ground truth)
    verdict: str = ""   # low | medium | high | critical
    score: int = 0
    hard_ids: list = field(default_factory=list)   # signals that drove the verdict
    error: str = ""     # non-empty -> file could not be analyzed

    def predicted(self, threshold: str) -> str:
        rank = VERDICT_RANK.get(self.verdict, 0)
        return PHISH if rank >= VERDICT_RANK[threshold] else HAM

    def outcome(self, threshold: str) -> str:
        """TP / FP / FN / TN for the given threshold."""
        pred = self.predicted(threshold)
        if self.label == PHISH:
            return "TP" if pred == PHISH else "FN"
        return "FP" if pred == PHISH else "TN"

    def to_dict(self) -> dict:
        return {"file": self.file, "label": self.label, "verdict": self.verdict,
                "score": self.score, "hard_ids": self.hard_ids, "error": self.error}


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        """Of the mails we flagged, how many really were phishing."""
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        """Of the real phishing mails, how many we caught."""
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Share of legitimate mail wrongly flagged - the metric users feel."""
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


@dataclass
class BenchResult:
    threshold: str
    cases: list
    missing: list = field(default_factory=list)   # labelled but file not found
    unlabeled: list = field(default_factory=list)  # .eml present, no label

    def metrics(self, threshold=None) -> Metrics:
        m = Metrics()
        t = threshold or self.threshold
        for c in self.cases:
            if c.error:
                continue
            key = c.outcome(t).lower()
            setattr(m, key, getattr(m, key) + 1)
        return m

    def sweep(self) -> list:
        """Same run scored at every threshold - picks the cut-off for you."""
        return [(t, self.metrics(t)) for t in THRESHOLDS]

    def failures(self, kind: str, threshold=None) -> list:
        """FP or FN cases, worst first (highest score)."""
        t = threshold or self.threshold
        rows = [c for c in self.cases if not c.error and c.outcome(t) == kind]
        return sorted(rows, key=lambda c: -c.score)

    @property
    def errors(self) -> list:
        return [c for c in self.cases if c.error]

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "corpus_size": len(self.cases),
            "metrics": self.metrics().to_dict(),
            "sweep": {t: m.to_dict() for t, m in self.sweep()},
            "false_positives": [c.to_dict() for c in self.failures("FP")],
            "false_negatives": [c.to_dict() for c in self.failures("FN")],
            "errors": [c.to_dict() for c in self.errors],
            "missing": self.missing,
            "unlabeled": self.unlabeled,
        }


# ---------------------------------------------------------------------------
# Label discovery
# ---------------------------------------------------------------------------

def load_labels_csv(path) -> dict:
    """Read ``file,label`` rows. A header row is detected and skipped."""
    path = Path(path)
    if not path.exists():
        raise BenchError("etiket dosyasi yok: " + str(path))
    labels = {}
    bad = []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for lineno, row in enumerate(csv.reader(fh), start=1):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            name = row[0].strip()
            raw = row[1] if len(row) > 1 else ""
            label = normalize_label(raw)
            if not label:
                # A header like "file,label" lands here; only complain when it
                # is not the very first row.
                if lineno == 1:
                    continue
                bad.append(str(lineno) + ": " + name + "," + str(raw))
                continue
            labels[name.replace("\\", "/")] = label
    if not labels:
        raise BenchError("etiket dosyasinda gecerli satir yok: " + str(path) +
                         (" (taninmayan: " + "; ".join(bad[:5]) + ")" if bad else ""))
    return labels


def labels_from_folders(root) -> dict:
    """Fallback layout: corpus/phish/*.eml and corpus/ham/*.eml."""
    root = Path(root)
    labels = {}
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        label = normalize_label(sub.name)
        if not label:
            continue
        for f in sorted(sub.rglob("*.eml")):
            labels[str(f.relative_to(root)).replace("\\", "/")] = label
    return labels


def discover_labels(corpus_dir, labels_path=None) -> dict:
    """CSV if given/present, else phish/ham subfolders."""
    corpus_dir = Path(corpus_dir)
    if labels_path:
        return load_labels_csv(labels_path)
    default_csv = corpus_dir / "labels.csv"
    if default_csv.exists():
        return load_labels_csv(default_csv)
    labels = labels_from_folders(corpus_dir)
    if not labels:
        raise BenchError(
            "etiket bulunamadi: " + str(corpus_dir) + " icinde labels.csv yok ve "
            "phish/ ham/ alt klasorleri de yok")
    return labels


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def run(corpus_dir, labels=None, labels_path=None, threshold="medium",
        online=False, ctx=None) -> BenchResult:
    """Analyze every labelled file and return the scored comparison."""
    if threshold not in VERDICT_RANK:
        raise BenchError("gecersiz esik: " + str(threshold) +
                         " (secenekler: " + ", ".join(VERDICT_RANK) + ")")
    corpus_dir = Path(corpus_dir)
    if not corpus_dir.is_dir():
        raise BenchError("klasor yok: " + str(corpus_dir))

    labels = labels if labels is not None else discover_labels(corpus_dir, labels_path)
    ctx = ctx if ctx is not None else analyzer.build_context()

    cases, missing = [], []
    for name in sorted(labels):
        path = corpus_dir / name
        if not path.is_file():
            missing.append(name)
            continue
        case = Case(file=name, label=labels[name])
        try:
            r = analyzer.analyze_file(path, online=online, ctx=ctx)
            case.verdict = r.verdict
            case.score = r.score
            case.hard_ids = [i.id for i in r.indicators if i.id not in SOFT_IDS]
        except Exception as exc:  # a corrupt sample must not abort the whole run
            case.error = type(exc).__name__ + ": " + str(exc)
        cases.append(case)

    labelled = set(labels)
    unlabeled = sorted(
        rel for rel in (
            str(p.relative_to(corpus_dir)).replace("\\", "/")
            for p in corpus_dir.rglob("*.eml")
        ) if rel not in labelled
    )
    return BenchResult(threshold=threshold, cases=cases, missing=missing,
                       unlabeled=unlabeled)
