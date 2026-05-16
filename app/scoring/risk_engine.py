from __future__ import annotations

from app.models.api_results import NormalizedThreatResult
from app.models.correlation import IOCActivitySummary


class RiskScoringEngine:
    """Computes threat risk independent from confidence."""

    def score(self, local_score: int, provider_results: list[NormalizedThreatResult], historical_context: IOCActivitySummary | None = None) -> int:
        if not provider_results:
            base_score = local_score
        else:
            provider_score = max((item.risk_score for item in provider_results), default=0)
            malicious_hits = sum(item.malicious for item in provider_results)
            suspicious_hits = sum(item.suspicious for item in provider_results)
            weighted = int((local_score * 0.4) + (provider_score * 0.6))
            consensus_bonus = min(20, malicious_hits * 3 + suspicious_hits)
            base_score = min(100, max(local_score, weighted + consensus_bonus))

        if historical_context and historical_context.ioc.total_observations > 1:
            if historical_context.risk_snapshot.peak_risk >= 65:
                base_score = min(100, base_score + 10)
            elif historical_context.trend.direction == "increasing":
                base_score = min(100, base_score + 5)
                
            if historical_context.campaign_cluster and len(historical_context.campaign_cluster.nodes) >= 2:
                # Graph penalty for being tied to recurring malicious infrastructure
                base_score = min(100, base_score + 15)

            if historical_context.attributions:
                # Penalty for being part of known threat families
                base_score = min(100, base_score + 25)

        return base_score

