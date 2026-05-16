from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from app.models.api_results import Indicator, NormalizedThreatResult


class ProviderCapability(StrEnum):
    URL_ANALYSIS = "url_analysis"
    DOMAIN_REPUTATION = "domain_reputation"
    IP_REPUTATION = "ip_reputation"
    URL_SCREENSHOT_METADATA = "url_screenshot_metadata"
    ASN_ENRICHMENT = "asn_enrichment"
    DOMAIN_REGISTRATION = "domain_registration"
    SCAN_SUBMISSION = "scan_submission"


class ProviderHealthStatus(StrEnum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DISABLED = "disabled"


@dataclass(frozen=True)
class ProviderHealthSnapshot:
    provider_name: str
    status: ProviderHealthStatus = ProviderHealthStatus.UNKNOWN
    success_rate: float | None = None
    average_latency_ms: int | None = None
    last_error: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class ProviderExecutionResult:
    provider_name: str
    indicator: Indicator
    result: NormalizedThreatResult | None
    status: str
    duration_ms: int
    timed_out: bool = False
    error: str | None = None
    reliability_weight: float = 0.0
    health: ProviderHealthSnapshot | None = None
