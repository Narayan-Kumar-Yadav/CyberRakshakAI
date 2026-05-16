from __future__ import annotations

import asyncio
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


class URLScanService:
    """Async urlscan.io URL enrichment with scan submission and lightweight polling."""

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, settings: Settings, http_client: HttpClient, redis: RedisClient) -> None:
        self.settings = settings
        self.http_client = http_client
        self.redis = redis

    async def analyze(self, indicator: Indicator) -> NormalizedThreatResult:
        if indicator.type != "url":
            return self._result(indicator, "error", 0, RiskLevel.UNKNOWN, ["urlscan supports URL indicators only."])
        if not self.settings.urlscan_api_key:
            return self._result(indicator, "not_configured", 0, RiskLevel.UNKNOWN, ["URLSCAN_API_KEY is not configured."])

        start = perf_counter()
        tags = {"provider": "urlscan", "indicator_type": indicator.type}
        logger.info("Provider started", **log_extra("provider.started", **tags))
        await increment_metric_safe(self.redis, "provider_call", tags, self.settings.metrics_ttl_seconds)

        cache_key = f"urlscan:{indicator.type}:{sha256_hash(indicator.value.lower())}"
        cached = await self.redis.get_json(cache_key)
        if cached:
            await increment_metric_safe(self.redis, "provider_cache_hit", tags, self.settings.metrics_ttl_seconds)
            duration = elapsed_ms(start)
            await record_provider_latency(self.redis, "urlscan", "cache_hit", duration, self.settings.metrics_ttl_seconds)
            logger.info("Provider completed", **log_extra("provider.completed", **tags, status="cache_hit", duration_ms=duration))
            return self._from_cache(indicator, cached)
        await increment_metric_safe(self.redis, "provider_cache_miss", tags, self.settings.metrics_ttl_seconds)

        try:
            submission = await self._submit_scan(indicator.value)
            if submission.get("status") != "ok":
                result = self._result(indicator, submission["status"], submission["risk_score"], submission["risk_level"], submission["signals"])
            else:
                result = await self._poll_scan(indicator, str(submission["uuid"]))
        except Exception as exc:
            logger.warning("urlscan lookup failed", **log_extra("provider.failed", **tags, error_type=type(exc).__name__))
            result = self._result(indicator, "error", 0, RiskLevel.UNKNOWN, ["urlscan lookup failed safely."])

        if result.status in {"ok", "pending", "not_found"}:
            await self.redis.set_json(cache_key, self._to_cache(result), ttl_seconds=60 * 60 * 6)
        duration = elapsed_ms(start)
        status_metric = "success" if result.status in {"ok", "pending", "not_found"} else "failure"
        await increment_metric_safe(self.redis, f"provider_{status_metric}", {**tags, "status": result.status}, self.settings.metrics_ttl_seconds)
        await record_provider_latency(self.redis, "urlscan", result.status, duration, self.settings.metrics_ttl_seconds)
        logger.info(
            "Provider completed",
            **log_extra("provider.completed", **tags, status=result.status, risk_score=result.risk_score, duration_ms=duration),
        )
        return result

    async def _submit_scan(self, url: str) -> dict[str, Any]:
        session = self.http_client.get_session()
        headers = {"API-Key": self.settings.urlscan_api_key or "", "Content-Type": "application/json"}
        payload = {"url": url, "visibility": self.settings.urlscan_visibility}
        async with session.post(f"{self.BASE_URL}/scan/", headers=headers, json=payload) as response:
            if response.status in {200, 201}:
                payload = await response.json()
                return {"status": "ok", "uuid": payload.get("uuid"), "result": payload.get("result")}
            if response.status in {401, 403}:
                message = "urlscan API key was rejected."
            elif response.status == 429:
                message = "urlscan rate limit reached."
            else:
                message = "urlscan is temporarily unavailable."
            logger.warning("urlscan submission error", **log_extra("provider.error_response", provider="urlscan", status=response.status))
            return {"status": "error", "risk_score": 0, "risk_level": RiskLevel.UNKNOWN, "signals": [message]}

    async def _poll_scan(self, indicator: Indicator, scan_uuid: str) -> NormalizedThreatResult:
        if not scan_uuid:
            return self._result(indicator, "pending", 10, RiskLevel.LOW, ["urlscan accepted the scan but did not return a scan ID."])

        session = self.http_client.get_session()
        for attempt in range(self.settings.urlscan_poll_attempts):
            if attempt > 0 and self.settings.urlscan_poll_delay_seconds:
                await asyncio.sleep(self.settings.urlscan_poll_delay_seconds)
            async with session.get(f"{self.BASE_URL}/result/{scan_uuid}/") as response:
                if response.status == 200:
                    return self._normalize(indicator, await response.json(), scan_uuid)
                if response.status == 404:
                    continue
                logger.warning("urlscan polling error", **log_extra("provider.error_response", provider="urlscan", status=response.status))
                return self._result(indicator, "error", 0, RiskLevel.UNKNOWN, ["urlscan result polling failed safely."])
        return NormalizedThreatResult(
            source="urlscan",
            indicator=indicator,
            status="pending",
            risk_score=10,
            risk_level=RiskLevel.LOW,
            signals=["urlscan accepted the scan and the result is still pending."],
            raw_reference=scan_uuid,
            confidence_hint=35,
            metadata={"scan_uuid": scan_uuid},
        )

    def _normalize(self, indicator: Indicator, payload: dict[str, Any], scan_uuid: str) -> NormalizedThreatResult:
        verdicts = payload.get("verdicts", {}) or {}
        overall = verdicts.get("overall", {}) or {}
        page = payload.get("page", {}) or {}
        task = payload.get("task", {}) or {}
        lists = payload.get("lists", {}) or {}
        score = int(overall.get("score", 0) or 0)
        malicious_flag = bool(overall.get("malicious", False))
        risk_score = min(100, max(score, 85 if malicious_flag else 0))
        suspicious = 1 if 35 <= risk_score < 75 else 0
        malicious = 1 if risk_score >= 75 else 0
        categories = [str(item) for item in lists.get("ips", [])[:3]]
        signals = [f"urlscan overall score: {score}."]
        if malicious_flag:
            signals.append("urlscan verdict marked this scan as malicious.")
        if page.get("domain"):
            signals.append(f"Resolved page domain: {page.get('domain')}.")
        screenshot_url = task.get("screenshotURL")
        if screenshot_url:
            signals.append("Screenshot metadata is available from urlscan.")
        return NormalizedThreatResult(
            source="urlscan",
            indicator=indicator,
            status="ok",
            risk_score=risk_score,
            risk_level=risk_from_score(risk_score),
            malicious=malicious,
            suspicious=suspicious,
            categories=categories,
            signals=signals,
            confidence_hint=70 if risk_score else 45,
            raw_reference=scan_uuid,
            metadata={
                "scan_uuid": scan_uuid,
                "page_domain": page.get("domain"),
                "page_ip": page.get("ip"),
                "asn": page.get("asn"),
                "screenshot_available": bool(screenshot_url),
                "screenshot_url": screenshot_url,
            },
        )

    def _result(
        self,
        indicator: Indicator,
        status: str,
        risk_score: int,
        risk_level: RiskLevel,
        signals: list[str],
    ) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source="urlscan",
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
            "raw_reference": result.raw_reference,
        }

    def _from_cache(self, indicator: Indicator, data: dict[str, Any]) -> NormalizedThreatResult:
        return NormalizedThreatResult(
            source="urlscan",
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
            raw_reference=data.get("raw_reference"),
        )

