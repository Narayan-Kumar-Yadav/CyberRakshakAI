from __future__ import annotations

from app.models.confidence import ConfidenceScore
from app.models.provider import ProviderExecutionResult
from app.models.risk_level import risk_from_score
from app.models.threat_report import ThreatReport
from app.models.correlation import IOCActivitySummary
from app.orchestration.enrichment_pipeline import EnrichmentResult


class ThreatReportBuilder:
    """Builds stable user-facing reports from enrichment and scoring outputs."""

    def build(
        self,
        enrichment: EnrichmentResult,
        risk_score: int,
        confidence: ConfidenceScore,
        ai_explanation: str | None = None,
        historical_context: IOCActivitySummary | None = None,
    ) -> ThreatReport:
        provider_results = enrichment.provider_results
        risk_level = risk_from_score(risk_score)
        recommendations = self._recommendations(
            enrichment.local_result.recommendations,
            enrichment.provider_executions,
            risk_score,
        )
        return ThreatReport(
            target=enrichment.local_result.indicator,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence_score=confidence.score,
            confidence_level=confidence.level,
            confidence_explanation=confidence.explanation,
            summary=self._summary(enrichment.local_result.indicator.type, risk_score, provider_results_count=len(provider_results), provider_hits=self._provider_hits(enrichment.provider_executions)),
            local_result=enrichment.local_result,
            provider_results=provider_results,
            provider_summary=self._provider_summary(enrichment.provider_executions),
            provider_executions=enrichment.provider_executions,
            partial_results=enrichment.partial_results,
            recommendations=recommendations,
            ai_explanation=ai_explanation,
            historical_context=historical_context,
        )

    def _provider_hits(self, executions: list[ProviderExecutionResult]) -> int:
        return sum(
            (execution.result.malicious + execution.result.suspicious)
            for execution in executions
            if execution.result is not None
        )

    def _summary(self, target_type: str, risk_score: int, provider_results_count: int, provider_hits: int) -> str:
        if provider_hits:
            return f"{target_type.title()} analysis found {provider_hits} malicious/suspicious provider detections."
        if provider_results_count:
            return f"{target_type.title()} analysis completed with provider enrichment and no malicious consensus."
        if risk_score >= 35:
            return f"{target_type.title()} analysis found suspicious behavioral or lexical signals."
        return f"{target_type.title()} analysis found no strong threat indicators."

    def _provider_summary(self, executions: list[ProviderExecutionResult]) -> dict[str, object]:
        completed = sum(1 for item in executions if item.result is not None)
        failed = sum(1 for item in executions if item.result is None)
        timed_out = sum(1 for item in executions if item.timed_out)
        providers = sorted({item.provider_name for item in executions})
        return {
            "requested": len(executions),
            "completed": completed,
            "failed": failed,
            "timed_out": timed_out,
            "providers": providers,
        }

    def _recommendations(
        self,
        local_recommendations: list[str],
        provider_executions: list[ProviderExecutionResult],
        risk_score: int,
    ) -> list[str]:
        recommendations = list(dict.fromkeys(local_recommendations))
        if risk_score >= 65:
            recommendations.insert(0, "Treat this as unsafe unless a trusted security team confirms otherwise.")
        if any(item.result and item.result.status == "pending" for item in provider_executions):
            recommendations.append("Re-check later because one or more provider analyses are still pending.")
        if any(item.result is None or item.status in {"not_configured", "unavailable", "error", "timeout"} for item in provider_executions):
            recommendations.append("Provider coverage was incomplete, so combine this result with manual verification.")
        return recommendations[:6]

