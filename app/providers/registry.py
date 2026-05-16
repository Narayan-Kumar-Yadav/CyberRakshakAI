from __future__ import annotations

import asyncio
import logging
from time import perf_counter

from app.models.api_results import Indicator
from app.models.provider import ProviderExecutionResult
from app.observability.json_logging import log_extra
from app.observability.metrics import increment_metric_safe, record_provider_latency
from app.observability.timing import elapsed_ms
from app.providers.base import ThreatProvider
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class ProviderRegistry:
    """Registers provider plugins and executes compatible providers concurrently."""

    def __init__(self, redis: RedisClient, metrics_ttl_seconds: int = 86400) -> None:
        self.redis = redis
        self.metrics_ttl_seconds = metrics_ttl_seconds
        self._providers: dict[str, ThreatProvider] = {}

    def register(self, provider: ThreatProvider) -> None:
        self._providers[provider.name] = provider

    def enabled_providers(self) -> list[ThreatProvider]:
        return [provider for provider in self._providers.values() if provider.enabled]

    async def analyze(self, indicators: list[Indicator]) -> list[ProviderExecutionResult]:
        tasks = []
        for indicator in indicators:
            for provider in self.enabled_providers():
                if indicator.type in provider.supported_indicator_types:
                    tasks.append(self._execute(provider, indicator))
        if not tasks:
            return []
        return list(await asyncio.gather(*tasks))

    async def _execute(self, provider: ThreatProvider, indicator: Indicator) -> ProviderExecutionResult:
        start = perf_counter()
        tags = {"provider": provider.name, "indicator_type": indicator.type}
        health = await provider.health_snapshot()
        logger.info("Provider execution started", **log_extra("provider.execution.started", **tags))
        try:
            result = await asyncio.wait_for(provider.analyze(indicator), timeout=provider.timeout_seconds)
            duration = elapsed_ms(start)
            status = result.status
            await increment_metric_safe(
                self.redis,
                "provider_execution_completed",
                {**tags, "status": status},
                ttl_seconds=self.metrics_ttl_seconds,
            )
            await record_provider_latency(
                self.redis,
                provider.name,
                status,
                duration,
                ttl_seconds=self.metrics_ttl_seconds,
            )
            logger.info(
                "Provider execution completed",
                **log_extra(
                    "provider.execution.completed",
                    **tags,
                    status=status,
                    duration_ms=duration,
                    risk_score=result.risk_score,
                ),
            )
            return ProviderExecutionResult(
                provider_name=provider.name,
                indicator=indicator,
                result=result,
                status=status,
                duration_ms=duration,
                reliability_weight=provider.reliability_weight,
                health=health,
            )
        except asyncio.TimeoutError:
            duration = elapsed_ms(start)
            await increment_metric_safe(
                self.redis,
                "provider_execution_timeout",
                tags,
                ttl_seconds=self.metrics_ttl_seconds,
            )
            await increment_metric_safe(
                self.redis,
                "provider_failure_rate",
                {**tags, "failure_type": "timeout"},
                ttl_seconds=self.metrics_ttl_seconds,
            )
            logger.warning(
                "Provider execution timed out",
                **log_extra("provider.timeout", **tags, duration_ms=duration),
            )
            return ProviderExecutionResult(
                provider_name=provider.name,
                indicator=indicator,
                result=None,
                status="timeout",
                duration_ms=duration,
                timed_out=True,
                error="Provider timed out.",
                reliability_weight=provider.reliability_weight,
                health=health,
            )
        except Exception as exc:
            duration = elapsed_ms(start)
            await increment_metric_safe(
                self.redis,
                "provider_execution_failed",
                {**tags, "error_type": type(exc).__name__},
                ttl_seconds=self.metrics_ttl_seconds,
            )
            await increment_metric_safe(
                self.redis,
                "provider_failure_rate",
                {**tags, "failure_type": "exception"},
                ttl_seconds=self.metrics_ttl_seconds,
            )
            logger.warning(
                "Provider execution failed",
                **log_extra("provider.execution.failed", **tags, error_type=type(exc).__name__, duration_ms=duration),
            )
            return ProviderExecutionResult(
                provider_name=provider.name,
                indicator=indicator,
                result=None,
                status="error",
                duration_ms=duration,
                error="Provider failed safely.",
                reliability_weight=provider.reliability_weight,
                health=health,
            )
