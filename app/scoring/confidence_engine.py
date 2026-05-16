from __future__ import annotations

from app.models.confidence import ConfidenceScore, confidence_from_score
from app.models.correlation import IOCActivitySummary
from app.models.provider import ProviderExecutionResult
from app.services.ioc_aging_service import IOCAgingService


class ConfidenceScoringEngine:
    """Scores how reliable the risk verdict is, separate from risk severity."""

    def __init__(self, aging_service: IOCAgingService | None = None) -> None:
        self.aging_service = aging_service or IOCAgingService()

    def score(self, provider_executions: list[ProviderExecutionResult], historical_context: IOCActivitySummary | None = None) -> ConfidenceScore:
        if not provider_executions:
            return ConfidenceScore(
                score=20,
                level=confidence_from_score(20),
                explanation="Low confidence because no external provider enrichment was applicable.",
                provider_coverage=0.0,
                consensus_strength=0.0,
                reliability_weight=0.0,
                factors=["local heuristics only"],
            )

        completed = [item for item in provider_executions if item.result is not None and item.status not in {"error", "timeout"}]
        positive = [
            item
            for item in completed
            if item.result and (item.result.malicious > 0 or item.result.suspicious > 0 or item.result.risk_score >= 35)
        ]
        coverage = len(completed) / len(provider_executions)
        reliability = sum(item.reliability_weight for item in completed) / max(1, len(provider_executions))
        consensus = len(positive) / max(1, len(completed))
        provider_diversity = len({item.provider_name for item in completed}) / max(1, len(provider_executions))
        confidence_hints = [
            item.result.confidence_hint
            for item in completed
            if item.result is not None and item.result.confidence_hint is not None
        ]
        hint_score = (sum(confidence_hints) / len(confidence_hints) / 100) if confidence_hints else 0.0
        agreement = self._agreement_strength(completed)
        score = int(
            (coverage * 30)
            + (reliability * 25)
            + (consensus * 15)
            + (provider_diversity * 15)
            + (agreement * 10)
            + (hint_score * 5)
        )

        historical_factors: list[str] = []
        if historical_context and historical_context.ioc.total_observations > 1:
            if historical_context.provider_correlation.agreement_score >= 0.75:
                score += 15
                historical_factors.append(f"historically stable consensus across {historical_context.ioc.total_observations} observations")
            elif historical_context.ioc.total_observations >= 3:
                score += 10
                historical_factors.append("corroborated by multiple past sightings")

        timeout_count = sum(1 for item in provider_executions if item.timed_out)
        failure_count = sum(1 for item in provider_executions if item.status in {"error", "timeout"} or item.result is None)
        score = max(0, score - timeout_count * 10 - failure_count * 5)

        if historical_context:
            decayed_score = self.aging_service.calculate_decayed_confidence(score, historical_context)
            if decayed_score < score:
                score = decayed_score
                from datetime import datetime
                try:
                    last_seen_dt = datetime.strptime(historical_context.ioc.last_seen_at, "%Y-%m-%d %H:%M:%S")
                    days_stale = (datetime.utcnow() - last_seen_dt).days
                    historical_factors.append(self.aging_service.get_decay_factor_description(days_stale))
                except ValueError:
                    pass

        factors: list[str] = []
        if coverage >= 0.75:
            factors.append("broad provider coverage")
        elif coverage > 0:
            factors.append("partial provider coverage")
        if consensus >= 0.5:
            factors.append("provider consensus on suspicious activity")
        if agreement >= 0.75:
            factors.append("providers agree on verdict direction")
        if provider_diversity >= 0.5:
            factors.append("diverse provider types responded")
        if reliability >= 0.75:
            factors.append("high-reliability providers responded")
        if timeout_count:
            factors.append("timeout penalties applied")
        if failure_count and not timeout_count:
            factors.append("incomplete enrichment penalty applied")
        factors.extend(historical_factors)
        if not factors:
            factors.append("limited corroborating intelligence")

        level = confidence_from_score(min(score, 100))
        explanation = f"{level.value} confidence based on " + ", ".join(factors) + "."
        return ConfidenceScore(
            score=min(score, 100),
            level=level,
            explanation=explanation,
            provider_coverage=round(coverage, 2),
            consensus_strength=round(consensus, 2),
            reliability_weight=round(reliability, 2),
            factors=factors,
        )

    def _agreement_strength(self, completed: list[ProviderExecutionResult]) -> float:
        if len(completed) <= 1:
            return 0.0
        verdicts = []
        for item in completed:
            if item.result is None:
                continue
            if item.result.risk_score >= 65 or item.result.malicious:
                verdicts.append("malicious")
            elif item.result.risk_score >= 35 or item.result.suspicious:
                verdicts.append("suspicious")
            else:
                verdicts.append("low")
        if not verdicts:
            return 0.0
        most_common = max(verdicts.count(verdict) for verdict in set(verdicts))
        return most_common / len(verdicts)
