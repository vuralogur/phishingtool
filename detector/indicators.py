"""The single unit of evidence produced by every check."""
from __future__ import annotations
from dataclasses import dataclass, asdict

from . import mitre

# Higher = more serious. Used to sort the report.
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Indicator:
    id: str          # stable slug, e.g. anchor_href_mismatch
    category: str    # auth | url | content | attachment | reputation
    severity: str    # low | medium | high | critical
    weight: int      # points added to the risk score
    evidence: str    # concrete, quoted proof from THIS email
    explanation: str # why it matters (human readable)
    technique: str = ""       # MITRE ATT&CK id, e.g. T1566.002 ("" = unmapped)
    technique_name: str = ""  # its ATT&CK display name

    def __post_init__(self):
        # Tag here rather than in each check: a new check gets its ATT&CK id for
        # free from detector/mitre.py, and no code path can forget to stamp it.
        if not self.technique:
            self.technique, self.technique_name = mitre.lookup(self.id)
        elif not self.technique_name:
            self.technique_name = mitre.NAMES.get(self.technique, "")

    def to_dict(self) -> dict:
        return asdict(self)
