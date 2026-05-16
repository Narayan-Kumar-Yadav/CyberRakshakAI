from __future__ import annotations

import base64
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


class VirusTotalService:
    """Async VirusTotal v3 integration with Redis caching and normalized output."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, settings: Settings, http_client: HttpClient, redis: RedisClient) -> None:
        self.settings = settings
        self.http_client = http_client
        self.redis = redis

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        if not self.settings.virustotal_api_key:
            return self._unavailable(indicator, "not_configured", "VIRUSTOTAL_API_KEY is not configured.")

        start = perf_counter()
        provider_tags = {"provider": "virustotal", "indicator_type": indicator.type}
        logger.info("Provider started", **log_extra("provider.started", **provider_tags))
        await increment_metric_safe(
            self.redis,
            "provider_call",
            provider_tags,
            ttl_seconds=self.settings.metrics_ttl_seconds,
        )

        cache_key = f"vt:{indicator.type}:{sha256_hash(indicator.value.lower())}"
        cached = await self.redis.get_json(cache_key)
        if cached:
            await increment_metric_safe(
                self.redis,
                "provider_cache_hit",
                provider_tags,
                ttl_seconds=self.settings.metrics_ttl_seconds,
            )
            duration = elapsed_ms(start)
            await record_provider_latency(
                self.redis,
                "virustotal",
                "cache_hit",
                duration,
                ttl_seconds=self.settings.metrics_ttl_seconds,
            )
            logger.info(
                "Provider completed",
                **log_extra("provider.completed", **provider_tags, status="cache_hit", duration_ms=duration),
            )
            return self._from_cache(indicator, cached)
        await increment_metric_safe(
            self.redis,
            "provider_cache_miss",
            provider_tags,
            ttl_seconds=self.settings.metrics_ttl_seconds,
        )

        try:
            if indicator.type == "url":
                result = await self._url_report(indicator)
            elif indicator.type == "domain":
                result = await self._object_report(indicator, f"/domains/{indicator.value.lower()}")
            elif indicator.type == "ip":
                result = await self._object_report(indicator, f"/ip_addresses/{indicator.value}")
            else:
                result = self._unavailable(indicator, "error", "VirusTotal supports URL, domain, and IP indicators.")
        except Exception as exc:  # Defensive boundary: do not leak provider internals to users.
            logger.warning(
                "VirusTotal lookup failed",
                **log_extra("provider.failed", **provider_tags, error_type=type(exc).__name__),
            )
            result = self._unavailable(indicator, "error", "VirusTotal lookup failed safely.")

        if result.status in {"ok", "not_found", "pending"}:
            await self.redis.set_json(cache_key, self._to_cache(result), ttl_seconds=60 * 60 * 6)
        status = "success" if result.status in {"ok", "not_found", "pending"} else "failure"
        duration = elapsed_ms(start)
        await increment_metric_safe(
            self.redis,
            f"provider_{status}",
            {**provider_tags, "status": result.status},
            ttl_seconds=self.settings.metrics_ttl_seconds,
        )
        await record_provider_latency(
            self.redis,
            "virustotal",
            result.status,
            duration,
            ttl_seconds=self.settings.metrics_ttl_seconds,
        )
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

    async def _url_report(self, indicator: Indicator) -> NormalizedThreatResult:
        url_id = base64.urlsafe_b64encode(indicator.value.encode("utf-8")).decode("ascii").rstrip("=")
        result = await self._object_report(indicator, f"/urls/{url_id}", allow_not_found=True)
        if result.status != "not_found":
            return result

        session = self.http_client.get_session()
        async with session.post(
            f"{self.BASE_URL}/urls",
            headers=self._headers(),
            data={"url": indicator.value},
        ) as response:
            if response.status in {200, 201}:
                payload = await response.json()
                analysis_id = payload.get("data", {}).get("id")
                return NormalizedThreatResult(
                    source="virustotal",
                    indicator=indicator,
                    status="pending",
                    risk_score=15,
                    risk_level=RiskLevel.LOW,
                    signals=["URL was submitted to VirusTotal and analysis is pending."],
                    raw_reference=str(analysis_id) if analysis_id else None,
                )
            return await self._response_error(indicator, response.status, await response.text())

    async def _object_report(
        self,
        indicator: Indicator,
        path: str,
        allow_not_found: bool = False,
    ) -> NormalizedThreatResult:
        session = self.http_client.get_session()
        async with session.get(f"{self.BASE_URL}{path}", headers=self._headers()) as response:
            if response.status == 200:
                payload = await response.json()
                return self._normalize(indicator, payload)
            if response.status == 404 and allow_not_found:
                return self._unavailable(indicator, "not_found", "No existing VirusTotal report found.")
            return await self._response_error(indicator, response.status, await response.text())

    def _normalize(self, indicator: Indicator, payload: dict[str, Any]) -> NormalizedThreatResult:
        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        reputation = int(attributes.get("reputation", 0) or 0)
        categories_raw = attributes.get("categories", {}) or {}
        categories = sorted({str(value) for value in categories_raw.values() if value})[:8]

        score = min(100, malicious * 20 + suspicious * 10 + max(0, -reputation))
        signals = [
            f"VirusTotal engines flagged malicious={malicious}, suspicious={suspicious}.",
        ]
        if categories:
            signals.append("Provider categories: " + ", ".join(categories))
        if reputation < 0:
            signals.append(f"Negative community/provider reputation: {reputation}.")

        return NormalizedThreatResult(
            source="virustotal",
            indicator=indicator,
            status="ok",
            risk_score=score,
            risk_level=risk_from_score(score),
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            categories=categories,
            signals=signals,
            confidence_hint=min(100, 50 + malicious * 10 + suspicious * 5 + min(20, harmless // 5)),
            metadata={
                "reputation": reputation,
                "harmless": harmless,
                "undetected": undetected,
            },
            raw_reference=str(data.get("id")) if data.get("id") else None,
        )

    async def _response_error(self, indicator: Indicator, status: int, body: str) -> NormalizedThreatResult:
        if status == 401:
            message = "VirusTotal API key was rejected."
        elif status == 429:
            message = "VirusTotal rate limit reached."
        elif status == 404:
            message = "No VirusTotal report found."
        else:
            message = "VirusTotal is temporarily unavailable."
        logger.warning("VirusTotal error", **log_extra("provider.error_response", provider="virustotal", status=status))
        return self._unavailable(indicator, "error" if status != 404 else "not_found", message)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.settings.virustotal_api_key or ""}

    def _unavailable(self, indicator: Indicator, status: str, error: str) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source="virustotal",
            indicator=indicator,
            status=status,  # type: ignore[arg-type]
            risk_score=0,
            risk_level=RiskLevel.UNKNOWN,
            error=error,
            signals=[error],
        )

    def _to_cache(self, result: NormalizedThreatResult) -> dict[str, Any]:
        return {
            "status": result.status,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level.value,
            "malicious": result.malicious,
            "suspicious": result.suspicious,
            "harmless": result.harmless,
            "undetected": result.undetected,
            "categories": result.categories,
            "signals": result.signals,
            "confidence_hint": result.confidence_hint,
            "metadata": result.metadata,
            "raw_reference": result.raw_reference,
            "error": result.error,
        }

    def _from_cache(self, indicator: Indicator, data: dict[str, Any]) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source="virustotal",
            indicator=indicator,
            status=data.get("status", "ok"),
            risk_score=int(data.get("risk_score", 0)),
            risk_level=RiskLevel(data.get("risk_level", RiskLevel.UNKNOWN.value)),
            malicious=int(data.get("malicious", 0)),
            suspicious=int(data.get("suspicious", 0)),
            harmless=int(data.get("harmless", 0)),
            undetected=int(data.get("undetected", 0)),
            categories=list(data.get("categories", [])),
            signals=[*list(data.get("signals", [])), "Result served from Redis cache."],
            confidence_hint=data.get("confidence_hint"),
            metadata=dict(data.get("metadata", {})),
            raw_reference=data.get("raw_reference"),
            error=data.get("error"),
        )
