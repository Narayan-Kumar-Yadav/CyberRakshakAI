from __future__ import annotations

from dataclasses import dataclass

from app.models.api_results import Indicator, IndicatorType, NormalizedThreatResult
from app.models.provider import ProviderCapability, ProviderHealthSnapshot, ProviderHealthStatus
from app.services.abuseipdb import AbuseIPDBService
from app.services.urlhaus import URLhausService
from app.services.urlscan import URLScanService
from app.services.virustotal import VirusTotalService


@dataclass
class VirusTotalProvider:
    service: VirusTotalService
    timeout_seconds: float
    enabled: bool = True
    name: str = "virustotal"
    reliability_weight: float = 0.90
    capabilities: frozenset[ProviderCapability] = frozenset(
        {
            ProviderCapability.URL_ANALYSIS,
            ProviderCapability.DOMAIN_REPUTATION,
            ProviderCapability.IP_REPUTATION,
        }
    )
    supported_indicator_types: frozenset[IndicatorType] = frozenset({"url", "domain", "ip"})

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        return await self.service.analyze(indicator)

    async def health_snapshot(self) -> ProviderHealthSnapshot:
        status = ProviderHealthStatus.HEALTHY if self.enabled else ProviderHealthStatus.DISABLED
        return ProviderHealthSnapshot(provider_name=self.name, status=status)


@dataclass
class URLhausProvider:
    service: URLhausService
    timeout_seconds: float
    enabled: bool = True
    name: str = "urlhaus"
    reliability_weight: float = 0.85
    capabilities: frozenset[ProviderCapability] = frozenset(
        {
            ProviderCapability.URL_ANALYSIS,
            ProviderCapability.DOMAIN_REPUTATION,
            ProviderCapability.IP_REPUTATION,
        }
    )
    supported_indicator_types: frozenset[IndicatorType] = frozenset({"url", "domain", "ip"})

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        return await self.service.analyze(indicator)

    async def health_snapshot(self) -> ProviderHealthSnapshot:
        status = ProviderHealthStatus.HEALTHY if self.enabled else ProviderHealthStatus.DISABLED
        return ProviderHealthSnapshot(provider_name=self.name, status=status)


@dataclass
class AbuseIPDBProvider:
    service: AbuseIPDBService
    timeout_seconds: float
    enabled: bool = True
    name: str = "abuseipdb"
    reliability_weight: float = 0.82
    capabilities: frozenset[ProviderCapability] = frozenset(
        {
            ProviderCapability.IP_REPUTATION,
            ProviderCapability.ASN_ENRICHMENT,
        }
    )
    supported_indicator_types: frozenset[IndicatorType] = frozenset({"ip"})

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        return await self.service.analyze(indicator)

    async def health_snapshot(self) -> ProviderHealthSnapshot:
        status = ProviderHealthStatus.HEALTHY if self.enabled else ProviderHealthStatus.DISABLED
        return ProviderHealthSnapshot(provider_name=self.name, status=status)


@dataclass
class URLScanProvider:
    service: URLScanService
    timeout_seconds: float
    enabled: bool = True
    name: str = "urlscan"
    reliability_weight: float = 0.78
    capabilities: frozenset[ProviderCapability] = frozenset(
        {
            ProviderCapability.URL_ANALYSIS,
            ProviderCapability.URL_SCREENSHOT_METADATA,
            ProviderCapability.SCAN_SUBMISSION,
            ProviderCapability.ASN_ENRICHMENT,
        }
    )
    supported_indicator_types: frozenset[IndicatorType] = frozenset({"url"})

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        return await self.service.analyze(indicator)

    async def health_snapshot(self) -> ProviderHealthSnapshot:
        status = ProviderHealthStatus.HEALTHY if self.enabled else ProviderHealthStatus.DISABLED
        return ProviderHealthSnapshot(provider_name=self.name, status=status)
