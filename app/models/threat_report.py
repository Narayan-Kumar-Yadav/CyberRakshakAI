from __future__ import annotations

from dataclasses import dataclass, field

from app.models.api_results import Indicator, LocalHeuristicResult, NormalizedThreatResult
from app.models.confidence import ConfidenceLevel
from app.models.correlation import IOCActivitySummary
from app.models.provider import ProviderExecutionResult
from app.models.risk_level import RiskLevel


@dataclass(frozen=True)
class ThreatReport:
    target: Indicator
    risk_score: int
    risk_level: RiskLevel
    confidence_score: int
    confidence_level: ConfidenceLevel
    confidence_explanation: str
    summary: str
    local_result: LocalHeuristicResult
    provider_results: list[NormalizedThreatResult] = field(default_factory=list)
    provider_summary: dict[str, object] = field(default_factory=dict)
    provider_executions: list[ProviderExecutionResult] = field(default_factory=list)
    partial_results: bool = False
    recommendations: list[str] = field(default_factory=list)
    ai_explanation: str | None = None
    historical_context: IOCActivitySummary | None = None

    def compact_dict(self) -> dict[str, object]:
        return {
            "target": {"type": self.target.type, "value": self.target.value},
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level.value,
            "confidence_explanation": self.confidence_explanation,
            "summary": self.summary,
            "partial_results": self.partial_results,
            "signals": self.local_result.signals,
            "provider_summary": self.provider_summary,
            "providers": [
                {
                    "source": item.source,
                    "indicator": {"type": item.indicator.type, "value": item.indicator.value},
                    "status": item.status,
                    "risk_score": item.risk_score,
                    "risk_level": item.risk_level.value,
                    "malicious": item.malicious,
                    "suspicious": item.suspicious,
                    "categories": item.categories,
                    "signals": item.signals,
                    "confidence_hint": item.confidence_hint,
                    "metadata": item.metadata,
                }
                for item in self.provider_results
            ],
            "recommendations": self.recommendations,
        }
