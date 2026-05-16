from __future__ import annotations

from typing import Protocol

from app.models.api_results import Indicator, IndicatorType, NormalizedThreatResult
from app.models.provider import ProviderCapability, ProviderHealthSnapshot


class ThreatProvider(Protocol):
    """Provider plugin contract used by the orchestration layer."""

    name: str
    capabilities: frozenset[ProviderCapability]
    supported_indicator_types: frozenset[IndicatorType]
    timeout_seconds: float
    reliability_weight: float
    enabled: bool

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        ...

    async def health_snapshot(self) -> ProviderHealthSnapshot:
        ...

