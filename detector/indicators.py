"""The single unit of evidence produced by every check."""
from __future__ import annotations
from dataclasses import dataclass, asdict

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

    def to_dict(self) -> dict:
        return asdict(self)
