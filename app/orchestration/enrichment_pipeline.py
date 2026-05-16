from __future__ import annotations

import logging
from dataclasses import dataclass

from app.models.api_results import Indicator, LocalHeuristicResult, NormalizedThreatResult
from app.models.provider import ProviderExecutionResult
from app.observability.json_logging import log_extra
from app.providers.registry import ProviderRegistry
from app.services.phishing import PhishingDetector

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EnrichmentResult:
    local_result: LocalHeuristicResult
    indicators: list[Indicator]
    provider_executions: list[ProviderExecutionResult]

    @property
    def provider_results(self) -> list[NormalizedThreatResult]:
        return [execution.result for execution in self.provider_executions if execution.result is not None]

    @property
    def partial_results(self) -> bool:
        return any(execution.result is None or execution.timed_out for execution in self.provider_executions)


class EnrichmentPipeline:
    """Classifies input, extracts indicators, and runs provider enrichment."""

    def __init__(self, phishing_detector: PhishingDetector, provider_registry: ProviderRegistry) -> None:
        self.phishing_detector = phishing_detector
        self.provider_registry = provider_registry

    async def enrich(self, text: str) -> EnrichmentResult:
        local = self.phishing_detector.assess_typed(text)
        indicators = self._indicators_for_enrichment(local.indicator, local.extracted_indicators)
        logger.info(
            "Threat analysis classified target",
            **log_extra(
                "analysis.classified",
                target_type=local.indicator.type,
                extracted_indicator_count=len(indicators),
            ),
        )
        provider_executions = await self.provider_registry.analyze(indicators)
        return EnrichmentResult(local, indicators, provider_executions)

    def _indicators_for_enrichment(self, target: Indicator, extracted: list[Indicator]) -> list[Indicator]:
        merged: list[Indicator] = []
        seen: set[tuple[str, str]] = set()
        for item in [target, *extracted]:
            if item.type == "message":
                continue
            key = (item.type, item.value.lower())
            if key not in seen:
                seen.add(key)
                merged.append(item)
        return merged[:8]

