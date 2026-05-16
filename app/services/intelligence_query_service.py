from __future__ import annotations

import logging
from typing import Optional

from app.models.correlation import (
    HistoricalRiskSnapshot,
    IOCActivitySummary,
    IOCProviderCorrelation,
    IOCTrend,
)
from app.models.ioc import IOCRecord
from app.observability.metrics import increment_metric_safe
from app.observability.timing import elapsed_ms
from app.repositories.fingerprint_repository import FingerprintRepository
from app.repositories.ioc_repository import IOCRepository
from app.repositories.relationship_repository import RelationshipRepository
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class IntelligenceQueryService:
    """Business logic for querying and aggregating historical intelligence."""

    def __init__(
        self,
        ioc_repository: IOCRepository,
        redis: RedisClient | None = None,
        rel_repository: RelationshipRepository | None = None,
        fp_repository: FingerprintRepository | None = None,
    ) -> None:
        self.ioc_repository = ioc_repository
        self.redis = redis
        self.rel_repository = rel_repository
        self.fp_repository = fp_repository

    async def get_ioc_summary(self, indicator_type: str, indicator_value: str) -> Optional[IOCActivitySummary]:
        """Fetch and summarize historical observations for a given IOC."""
        import time
        start = time.perf_counter()
        
        if self.redis:
            await increment_metric_safe(self.redis, "ioc_query_count", {"type": indicator_type})
            
        ioc = await self.ioc_repository.get_ioc(indicator_type, indicator_value)
        if not ioc:
            if self.redis:
                await increment_metric_safe(self.redis, "ioc_query_miss", {"type": indicator_type})
            return None

        observations = await self.ioc_repository.get_ioc_history(ioc.id, limit=50)

        if self.redis:
            await increment_metric_safe(self.redis, "ioc_query_hit", {"type": indicator_type, "obs_count": len(observations)})
            if len(observations) > 1:
                await increment_metric_safe(self.redis, "repeated_ioc_detected", {"type": indicator_type})

        trend = self._calculate_trend(observations)
        provider_corr = self._calculate_correlation(observations)

        avg_risk = sum(obs.risk_score for obs in observations) // len(observations) if observations else 0
        peak_risk = max((obs.risk_score for obs in observations), default=0)
        risk_snapshot = HistoricalRiskSnapshot(
            average_risk=avg_risk,
            peak_risk=peak_risk,
            first_seen=ioc.first_seen_at,
            last_seen=ioc.last_seen_at,
        )

        cluster = None
        if self.rel_repository:
            cluster = await self.rel_repository.get_campaign_cluster(ioc.id)

        attributions = []
        if self.fp_repository:
            attributions = await self.fp_repository.get_attributions(ioc.id)

        if self.redis:
            duration = elapsed_ms(start)
            await increment_metric_safe(self.redis, "ioc_query_latency", {"type": indicator_type, "ms": str(int(duration))})

        return IOCActivitySummary(
            ioc=ioc,
            recent_observations=observations,
            trend=trend,
            provider_correlation=provider_corr,
            risk_snapshot=risk_snapshot,
            campaign_cluster=cluster,
            attributions=attributions,
        )

    def _calculate_trend(self, observations: list) -> IOCTrend:
        if len(observations) < 2:
            return IOCTrend(direction="insufficient_data", velocity=0.0)

        # Sort chronologically to compute trends
        chronological = sorted(observations, key=lambda x: x.created_at)
        mid = len(chronological) // 2
        first_half = chronological[:mid]
        second_half = chronological[mid:]

        first_avg = sum(obs.risk_score for obs in first_half) / max(1, len(first_half))
        second_avg = sum(obs.risk_score for obs in second_half) / max(1, len(second_half))

        diff = second_avg - first_avg
        if abs(diff) < 5:
            direction = "stable"
        elif diff > 0:
            direction = "increasing"
        else:
            direction = "decreasing"

        variance = sum((obs.risk_score - second_avg) ** 2 for obs in second_half) / max(1, len(second_half))
        if variance > 400:  # standard deviation > 20
            direction = "volatile"

        return IOCTrend(direction=direction, velocity=round(diff, 2))

    def _calculate_correlation(self, observations: list) -> IOCProviderCorrelation:
        if not observations:
            return IOCProviderCorrelation(agreement_score=0.0, most_frequent_confidence_level="unknown")

        confidences = [obs.confidence_level for obs in observations]
        most_frequent = max(set(confidences), key=confidences.count)
        agreement = confidences.count(most_frequent) / len(confidences)

        return IOCProviderCorrelation(
            agreement_score=round(agreement, 2),
            most_frequent_confidence_level=most_frequent,
        )
