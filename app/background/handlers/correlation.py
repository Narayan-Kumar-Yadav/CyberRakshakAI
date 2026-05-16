from __future__ import annotations

import logging
import time

from app.models.api_results import Indicator, NormalizedThreatResult
from app.models.lifecycle import BackgroundTask
from app.models.risk_level import RiskLevel
from app.observability.metrics import increment_metric_safe
from app.observability.timing import elapsed_ms
from app.services.fingerprinting import FingerprintingService
from app.services.infrastructure_correlation import InfrastructureCorrelationService
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class CorrelationJobHandler:
    """Handles background tasks for building the intelligence graph."""

    def __init__(
        self,
        correlation_service: InfrastructureCorrelationService,
        fp_service: FingerprintingService | None = None,
        redis: RedisClient | None = None,
    ) -> None:
        self.correlation_service = correlation_service
        self.fp_service = fp_service
        self.redis = redis

    async def handle(self, task: BackgroundTask) -> None:
        source_ioc_id = task.payload.get("source_ioc_id")
        indicator_type = task.payload.get("indicator_type")
        provider_results_dicts = task.payload.get("provider_results", [])

        if not source_ioc_id or not indicator_type:
            logger.warning("Invalid payload for correlation job")
            return

        # Reconstruct NormalizedThreatResult objects
        provider_results = []
        for p_dict in provider_results_dicts:
            ind_dict = p_dict.get("indicator", {})
            provider_results.append(
                NormalizedThreatResult(
                    source=p_dict.get("source", "unknown"),
                    indicator=Indicator(type=ind_dict.get("type", "url"), value=ind_dict.get("value", "")),
                    status=p_dict.get("status", "error"),
                    risk_score=p_dict.get("risk_score", 0),
                    risk_level=RiskLevel(p_dict.get("risk_level", "low")),
                    malicious=p_dict.get("malicious", 0),
                    suspicious=p_dict.get("suspicious", 0),
                    metadata=p_dict.get("metadata", {}),
                )
            )

        start = time.perf_counter()

        await self.correlation_service.correlate_from_enrichment(source_ioc_id, indicator_type, provider_results)

        if self.fp_service:
            fp = await self.fp_service.generate_and_persist(source_ioc_id, provider_results)
            base_risk = max([pr.risk_score for pr in provider_results], default=0)
            await self.fp_service.calculate_similarity_and_attribute(fp, base_risk)

        if self.redis:
            await increment_metric_safe(self.redis, "graph_traversal_latency", {"ms": str(int(elapsed_ms(start)))})
