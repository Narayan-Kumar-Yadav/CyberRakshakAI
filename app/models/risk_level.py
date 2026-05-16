from __future__ import annotations

from enum import StrEnum


class RiskLevel(StrEnum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


def risk_from_score(score: int) -> RiskLevel:
    if score >= 85:
        return RiskLevel.CRITICAL
    if score >= 65:
        return RiskLevel.HIGH
    if score >= 35:
        return RiskLevel.MEDIUM
    if score >= 1:
        return RiskLevel.LOW
    return RiskLevel.UNKNOWN

