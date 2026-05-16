from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.observability.timing import latency_bucket
from app.services.redis_cache import RedisClient


async def increment_metric_safe(
    redis: RedisClient,
    name: str,
    tags: Mapping[str, Any] | None = None,
    ttl_seconds: int | None = None,
) -> None:
    try:
        await redis.increment_metric(name, tags=tags, ttl_seconds=ttl_seconds)
    except Exception:
        # Metrics must never break request handling.
        return


async def record_provider_latency(
    redis: RedisClient,
    provider: str,
    status: str,
    duration_ms: int,
    ttl_seconds: int | None = None,
) -> None:
    await increment_metric_safe(
        redis,
        "provider_latency_bucket",
        {"provider": provider, "status": status, "bucket": latency_bucket(duration_ms)},
        ttl_seconds=ttl_seconds,
    )
