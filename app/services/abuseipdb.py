from __future__ import annotations

import logging
from time import perf_counter
from typing import Any

from app.config import Settings
from app.models.api_results import Indicator, NormalizedThreatResult
from app.models.risk_level import RiskLevel, risk_from_score
from app.observability.json_logging import log_extra
from app.observability.metrics import increment_metric_safe, record_provider_latency
from app.observability.timing import elapsed_ms
from app.services.http_client import HttpClient
from app.services.redis_cache import RedisClient
from app.utils.security import sha256_hash

logger = logging.getLogger(__name__)


class AbuseIPDBService:
    """Async AbuseIPDB IP reputation integration with normalized output."""

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, settings: Settings, http_client: HttpClient, redis: RedisClient) -> None:
        self.settings = settings
        self.http_client = http_client
        self.redis = redis

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        if indicator.type != "ip":
            return self._result(indicator, "error", 0, RiskLevel.UNKNOWN, ["AbuseIPDB supports IP indicators only."])
        if not self.settings.abuseipdb_api_key:
            return self._result(indicator, "not_configured", 0, RiskLevel.UNKNOWN, ["ABUSEIPDB_API_KEY is not configured."])

        start = perf_counter()
        tags = {"provider": "abuseipdb", "indicator_type": indicator.type}
        logger.info("Provider started", **log_extra("provider.started", **tags))
        await increment_metric_safe(self.redis, "provider_call", tags, ttl_seconds=self.settings.metrics_ttl_seconds)

        cache_key = f"abuseipdb:{indicator.type}:{sha256_hash(indicator.value.lower())}"
        cached = await self.redis.get_json(cache_key)
        if cached:
            await increment_metric_safe(self.redis, "provider_cache_hit", tags, ttl_seconds=self.settings.metrics_ttl_seconds)
            duration = elapsed_ms(start)
            await record_provider_latency(self.redis, "abuseipdb", "cache_hit", duration, self.settings.metrics_ttl_seconds)
            logger.info("Provider completed", **log_extra("provider.completed", **tags, status="cache_hit", duration_ms=duration))
            return self._from_cache(indicator, cached)
        await increment_metric_safe(self.redis, "provider_cache_miss", tags, ttl_seconds=self.settings.metrics_ttl_seconds)

        try:
            session = self.http_client.get_session()
            headers = {"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"}
            params = {"ipAddress": indicator.value, "maxAgeInDays": "90", "verbose": "true"}
            async with session.get(self.BASE_URL, headers=headers, params=params) as response:
                if response.status == 200:
                    result = self._normalize(indicator, await response.json())
                else:
                    result = self._error_result(indicator, response.status)
        except Exception as exc:
            logger.warning(
                "AbuseIPDB lookup failed",
                **log_extra("provider.failed", **tags, error_type=type(exc).__name__),
            )
            result = self._result(indicator, "error", 0, RiskLevel.UNKNOWN, ["AbuseIPDB lookup failed safely."])

        if result.status in {"ok", "not_found"}:
            await self.redis.set_json(cache_key, self._to_cache(result), ttl_seconds=60 * 60 * 6)
        duration = elapsed_ms(start)
        status_metric = "success" if result.status in {"ok", "not_found"} else "failure"
        await increment_metric_safe(self.redis, f"provider_{status_metric}", {**tags, "status": result.status}, self.settings.metrics_ttl_seconds)
        await record_provider_latency(self.redis, "abuseipdb", result.status, duration, self.settings.metrics_ttl_seconds)
        logger.info(
            "Provider completed",
            **log_extra("provider.completed", **tags, status=result.status, risk_score=result.risk_score, duration_ms=duration),
        )
        return result

    def _normalize(self, indicator: Indicator, payload: dict[str, Any]) -> NormalizedThreatResult:
        data = payload.get("data", {}) or {}
        abuse_score = int(data.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(data.get("totalReports", 0) or 0)
        distinct_users = int(data.get("numDistinctUsers", 0) or 0)
        risk_score = min(100, max(abuse_score, min(30, total_reports * 2) + min(15, distinct_users)))
        malicious = 1 if risk_score >= 75 else 0
        suspicious = 1 if 25 <= risk_score < 75 else 0
        categories = [str(item) for item in [data.get("usageType"), data.get("countryCode")] if item]
        signals = [
            f"Abuse confidence score: {abuse_score}.",
            f"Reports in last 90 days: {total_reports}.",
        ]
        if distinct_users:
            signals.append(f"Distinct reporting users: {distinct_users}.")
        if not total_reports and abuse_score == 0:
            signals.append("No AbuseIPDB abuse reports found in the selected window.")
        return NormalizedThreatResult(
            source="abuseipdb",
            indicator=indicator,
            status="ok",
            risk_score=risk_score,
            risk_level=risk_from_score(risk_score),
            malicious=malicious,
            suspicious=suspicious,
            categories=categories[:8],
            signals=signals,
            confidence_hint=min(100, 40 + min(40, total_reports * 4) + min(20, distinct_users * 2)),
            metadata={
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "country_code": data.get("countryCode"),
            },
        )

    def _error_result(self, indicator: Indicator, status: int) -> NormalizedThreatResult:
        if status in {401, 403}:
            message = "AbuseIPDB API key was rejected."
        elif status == 429:
            message = "AbuseIPDB rate limit reached."
        else:
            message = "AbuseIPDB is temporarily unavailable."
        logger.warning("AbuseIPDB error", **log_extra("provider.error_response", provider="abuseipdb", status=status))
        return self._result(indicator, "error", 0, RiskLevel.UNKNOWN, [message])

    def _result(
        self,
        indicator: Indicator,
        status: str,
        risk_score: int,
        risk_level: RiskLevel,
        signals: list[str],
    ) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source="abuseipdb",
            indicator=indicator,
            status=status,  # type: ignore[arg-type]
            risk_score=risk_score,
            risk_level=risk_level,
            signals=signals,
        )

    def _to_cache(self, result: NormalizedThreatResult) -> dict[str, Any]:
        return {
            "status": result.status,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level.value,
            "malicious": result.malicious,
            "suspicious": result.suspicious,
            "categories": result.categories,
            "signals": result.signals,
            "confidence_hint": result.confidence_hint,
            "metadata": result.metadata,
        }

    def _from_cache(self, indicator: Indicator, data: dict[str, Any]) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source="abuseipdb",
            indicator=indicator,
            status=data.get("status", "ok"),
            risk_score=int(data.get("risk_score", 0)),
            risk_level=RiskLevel(data.get("risk_level", RiskLevel.UNKNOWN.value)),
            malicious=int(data.get("malicious", 0)),
            suspicious=int(data.get("suspicious", 0)),
            categories=list(data.get("categories", [])),
            signals=[*list(data.get("signals", [])), "Result served from Redis cache."],
            confidence_hint=data.get("confidence_hint"),
            metadata=dict(data.get("metadata", {})),
        )

