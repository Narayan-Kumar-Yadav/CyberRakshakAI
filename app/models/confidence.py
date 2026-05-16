from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ConfidenceLevel(StrEnum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


def confidence_from_score(score: int) -> ConfidenceLevel:
    if score >= 75:
        return ConfidenceLevel.HIGH
    if score >= 45:
        return ConfidenceLevel.MEDIUM
    if score >= 1:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.UNKNOWN


@dataclass(frozen=True)
class ConfidenceScore:
    score: int
    level: ConfidenceLevel
    explanation: str
    provider_coverage: float
    consensus_strength: float
    reliability_weight: float
    factors: list[str] = field(default_factory=list)

