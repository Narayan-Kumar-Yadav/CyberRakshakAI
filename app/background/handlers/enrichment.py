from __future__ import annotations

import logging

from app.models.api_results import Indicator
from app.models.lifecycle import BackgroundTask
from app.observability.metrics import increment_metric_safe
from app.repositories.ioc_repository import IOCRepository
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class EnrichmentJobHandler:
    def __init__(self, ioc_repo: IOCRepository, providers: dict, redis: RedisClient | None = None) -> None:
        self.ioc_repo = ioc_repo
        self.providers = providers
        self.redis = redis

    async def handle(self, task: BackgroundTask) -> None:
        provider_name = task.payload.get("provider_name")
        target_ioc_id = task.payload.get("target_ioc_id")
        indicator_type = task.payload.get("indicator_type")
        indicator_value = task.payload.get("indicator_value")

        if not provider_name or provider_name not in self.providers:
            logger.warning(f"Unsupported provider for deferred enrichment: {provider_name}")
            return

        provider = self.providers[provider_name]
        indicator = Indicator(type=indicator_type, value=indicator_value)
        result = await provider.analyze(indicator)

        if result.status == "pending" or result.result is None:
            # Raising an exception forces the worker to mark it as failed and retry it later.
            raise RuntimeError("Provider analysis still pending or unavailable")

        # Provider completed successfully, record the final observation!
        await self.ioc_repo.record_observation(
            target_ioc_id,
            provider_hits=1 if result.result.malicious or result.result.suspicious else 0,
            risk_score=result.result.risk_score,
            confidence_score=result.result.confidence_hint or 50,
            confidence_level="Moderate",
        )

        if self.redis:
            await increment_metric_safe(self.redis, "deferred_enrichment_completed", {"provider": provider_name})
