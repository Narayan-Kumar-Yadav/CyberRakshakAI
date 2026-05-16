from __future__ import annotations

import logging
from time import perf_counter
from typing import Any

from app.models.api_results import Indicator, NormalizedThreatResult
from app.models.risk_level import RiskLevel
from app.observability.json_logging import log_extra
from app.observability.metrics import increment_metric_safe, record_provider_latency
from app.observability.timing import elapsed_ms
from app.services.http_client import HttpClient
from app.services.redis_cache import RedisClient
from app.utils.security import sha256_hash

logger = logging.getLogger(__name__)


class URLhausService:
    """Public abuse.ch URLhaus integration for malware URL and host reputation."""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, http_client: HttpClient, redis: RedisClient) -> None:
        self.http_client = http_client
        self.redis = redis

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        if indicator.type not in {"url", "domain", "ip"}:
            return self._result(indicator, "error", 0, RiskLevel.UNKNOWN, ["URLhaus supports URL, domain, and IP indicators."])

        start = perf_counter()
        provider_tags = {"provider": "urlhaus", "indicator_type": indicator.type}
        logger.info("Provider started", **log_extra("provider.started", **provider_tags))
        await increment_metric_safe(self.redis, "provider_call", provider_tags)

        cache_key = f"urlhaus:{indicator.type}:{sha256_hash(indicator.value.lower())}"
        cached = await self.redis.get_json(cache_key)
        if cached:
            await increment_metric_safe(self.redis, "provider_cache_hit", provider_tags)
            duration = elapsed_ms(start)
            await record_provider_latency(self.redis, "urlhaus", "cache_hit", duration)
            logger.info(
                "Provider completed",
                **log_extra("provider.completed", **provider_tags, status="cache_hit", duration_ms=duration),
            )
            return self._from_cache(indicator, cached)
        await increment_metric_safe(self.redis, "provider_cache_miss", provider_tags)

        try:
            path = "/url/" if indicator.type == "url" else "/host/"
            form_key = "url" if indicator.type == "url" else "host"
            session = self.http_client.get_session()
            async with session.post(f"{self.BASE_URL}{path}", data={form_key: indicator.value}) as response:
                if response.status >= 400:
                    logger.warning(
                        "URLhaus error",
                        **log_extra("provider.error_response", **provider_tags, status=response.status),
                    )
                    result = self._result(
                        indicator,
                        "error",
                        0,
                        RiskLevel.UNKNOWN,
                        ["URLhaus is temporarily unavailable."],
                    )
                else:
                    result = self._normalize(indicator, await response.json())
        except Exception as exc:
            logger.warning(
                "URLhaus lookup failed",
                **log_extra("provider.failed", **provider_tags, error_type=type(exc).__name__),
            )
            result = self._result(indicator, "error", 0, RiskLevel.UNKNOWN, ["URLhaus lookup failed safely."])

        if result.status in {"ok", "not_found"}:
            await self.redis.set_json(cache_key, self._to_cache(result), ttl_seconds=60 * 60 * 6)
        status = "success" if result.status in {"ok", "not_found"} else "failure"
        duration = elapsed_ms(start)
        await increment_metric_safe(self.redis, f"provider_{status}", {**provider_tags, "status": result.status})
        await record_provider_latency(self.redis, "urlhaus", result.status, duration)
        logger.info(
            "Provider completed",
            **log_extra(
                "provider.completed",
                **provider_tags,
                status=result.status,
                risk_score=result.risk_score,
                duration_ms=duration,
            ),
        )
        return result

    def _normalize(self, indicator: Indicator, payload: dict[str, Any]) -> NormalizedThreatResult:
        query_status = str(payload.get("query_status", "unknown"))
        if query_status in {"no_results", "invalid_url", "invalid_host"}:
            return self._result(indicator, "not_found", 0, RiskLevel.UNKNOWN, ["No URLhaus listing found."])
        if query_status != "ok":
            return self._result(indicator, "error", 0, RiskLevel.UNKNOWN, [f"URLhaus returned status: {query_status}."])

        url_count = int(payload.get("url_count", 0) or 0)
        threat = str(payload.get("threat", "") or "")
        tags = [str(item) for item in payload.get("tags", []) if item]
        blacklists = payload.get("blacklists", {}) or {}
        listed_count = sum(1 for value in blacklists.values() if str(value).lower() == "listed")
        score = min(100, 80 + min(15, url_count) + listed_count * 5)
        signals = ["Indicator is listed by URLhaus."]
        if threat:
            signals.append(f"Threat type: {threat}.")
        if tags:
            signals.append("Tags: " + ", ".join(tags[:8]))
        if url_count:
            signals.append(f"Related malicious URL count: {url_count}.")

        return self._result(
            indicator=indicator,
            status="ok",
            risk_score=score,
            risk_level=RiskLevel.CRITICAL if score >= 85 else RiskLevel.HIGH,
            signals=signals,
            categories=[threat, *tags][:8],
            malicious=max(1, url_count or listed_count),
            confidence_hint=min(100, 75 + min(20, url_count)),
        )

    def _result(
        self,
        indicator: Indicator,
        status: str,
        risk_score: int,
        risk_level: RiskLevel,
        signals: list[str],
        categories: list[str] | None = None,
        malicious: int = 0,
        confidence_hint: int | None = None,
    ) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source="urlhaus",
            indicator=indicator,
            status=status,  # type: ignore[arg-type]
            risk_score=risk_score,
            risk_level=risk_level,
            malicious=malicious,
            categories=[item for item in (categories or []) if item],
            signals=signals,
            confidence_hint=confidence_hint,
        )

    def _to_cache(self, result: NormalizedThreatResult) -> dict[str, Any]:
        return {
            "status": result.status,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level.value,
            "malicious": result.malicious,
            "categories": result.categories,
            "signals": result.signals,
            "confidence_hint": result.confidence_hint,
        }

    def _from_cache(self, indicator: Indicator, data: dict[str, Any]) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source="urlhaus",
            indicator=indicator,
            status=data.get("status", "ok"),
            risk_score=int(data.get("risk_score", 0)),
            risk_level=RiskLevel(data.get("risk_level", RiskLevel.UNKNOWN.value)),
            malicious=int(data.get("malicious", 0)),
            categories=list(data.get("categories", [])),
            signals=[*list(data.get("signals", [])), "Result served from Redis cache."],
            confidence_hint=data.get("confidence_hint"),
        )
