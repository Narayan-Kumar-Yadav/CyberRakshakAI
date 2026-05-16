from __future__ import annotations

import asyncio
import unittest
from pathlib import Path

from app.models.api_results import Indicator, NormalizedThreatResult
from app.models.provider import ProviderCapability, ProviderHealthSnapshot, ProviderExecutionResult
from app.models.risk_level import RiskLevel
from app.providers.registry import ProviderRegistry
from app.scoring.confidence_engine import ConfidenceScoringEngine
from app.services.redis_cache import RedisClient


class InMemoryRedis(RedisClient):
    def __init__(self) -> None:
        super().__init__("redis://example.invalid", metrics_enabled=False)

    async def increment_with_ttl(self, key: str, ttl_seconds: int) -> int:
        return 1


class FastProvider:
    name = "fast"
    capabilities = frozenset({ProviderCapability.URL_ANALYSIS})
    supported_indicator_types = frozenset({"url"})
    timeout_seconds = 1.0
    reliability_weight = 0.9
    enabled = True

    async def health_snapshot(self) -> ProviderHealthSnapshot:
        return ProviderHealthSnapshot(provider_name=self.name)

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source=self.name,
            indicator=indicator,
            status="ok",
            risk_score=80,
            risk_level=RiskLevel.HIGH,
            malicious=1,
            confidence_hint=80,
        )


class SlowProvider(FastProvider):
    name = "slow"
    timeout_seconds = 0.01
    reliability_weight = 0.5

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        await asyncio.sleep(0.1)
        return await super().analyze(indicator)


class ProviderArchitectureTests(unittest.IsolatedAsyncioTestCase):
    async def test_provider_registry_isolates_timeout(self) -> None:
        registry = ProviderRegistry(InMemoryRedis())
        registry.register(FastProvider())
        registry.register(SlowProvider())

        results = await registry.analyze([Indicator("https://example.test", "url")])

        self.assertEqual(len(results), 2)
        self.assertTrue(any(item.timed_out for item in results))
        self.assertTrue(any(item.result and item.result.source == "fast" for item in results))

    def test_confidence_scoring_penalizes_partial_enrichment(self) -> None:
        indicator = Indicator("https://example.test", "url")
        completed = ProviderExecutionResult(
            provider_name="fast",
            indicator=indicator,
            result=NormalizedThreatResult("fast", indicator, "ok", 80, RiskLevel.HIGH, malicious=1, confidence_hint=80),
            status="ok",
            duration_ms=10,
            reliability_weight=0.9,
        )
        timed_out = ProviderExecutionResult(
            provider_name="slow",
            indicator=indicator,
            result=None,
            status="timeout",
            duration_ms=10,
            timed_out=True,
            reliability_weight=0.5,
        )

        confidence = ConfidenceScoringEngine().score([completed, timed_out])

        self.assertGreater(confidence.score, 0)
        self.assertIn("timeout penalties applied", confidence.factors)

    def test_normalized_result_has_provider_metadata_isolation(self) -> None:
        indicator = Indicator("https://example.test", "url")
        result = NormalizedThreatResult(
            source="urlscan",
            indicator=indicator,
            status="ok",
            risk_score=70,
            risk_level=RiskLevel.HIGH,
            metadata={"screenshot_available": True},
        )

        self.assertEqual(result.source, "urlscan")
        self.assertEqual(result.metadata["screenshot_available"], True)
        self.assertLessEqual(result.risk_score, 100)

    def test_threat_intelligence_service_is_facade_only(self) -> None:
        source = Path("app/services/threat_intelligence.py").read_text(encoding="utf-8")

        self.assertNotIn("def _score", source)
        self.assertNotIn("def _run_providers", source)
        self.assertIn("AnalysisOrchestrator", source)


if __name__ == "__main__":
    unittest.main()

