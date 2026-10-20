from __future__ import annotations

import math
from collections.abc import Iterable

SEVERITY_WEIGHTS = {"INFO": 0, "LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITY_WEIGHTS)}


def alert_risk(severity: str, confidence: int = 70) -> int:
    base = SEVERITY_WEIGHTS.get(severity.upper(), 0)
    return min(100, round(base * (0.55 + max(0, min(confidence, 100)) / 100)))


def system_risk(severities: Iterable[str]) -> int:
    weighted = sum(SEVERITY_WEIGHTS.get(item.upper(), 0) for item in severities)
    return min(100, round(100 * (1 - math.exp(-weighted / 75))))


def highest_severity(severities: Iterable[str]) -> str:
    return max(severities, key=lambda value: SEVERITY_ORDER.get(value.upper(), 0), default="INFO").upper()
