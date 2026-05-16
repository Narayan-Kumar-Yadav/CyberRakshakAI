from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from app.models.risk_level import RiskLevel

IndicatorType = Literal["url", "domain", "ip", "message"]
SourceStatus = Literal["ok", "not_found", "unavailable", "error", "not_configured", "pending"]


@dataclass(frozen=True)
class Indicator:
    value: str
    type: IndicatorType


@dataclass(frozen=True)
class NormalizedThreatResult:
    """Common shape for all threat-intelligence providers."""

    source: str
    indicator: Indicator
    status: SourceStatus
    risk_score: int
    risk_level: RiskLevel
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    categories: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    confidence_hint: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_reference: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class LocalHeuristicResult:
    indicator: Indicator
    risk_score: int
    risk_level: RiskLevel
    signals: list[str]
    extracted_indicators: list[Indicator]
    recommendations: list[str]
