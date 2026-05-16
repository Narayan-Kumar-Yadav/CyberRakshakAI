from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from redis.asyncio import Redis

from app.utils.security import sha256_hash


class RedisClient:
    """Thin async Redis wrapper for cache, rate limits, and spam controls."""

    def __init__(
        self,
        redis_url: str,
        metrics_enabled: bool = True,
        default_metrics_ttl_seconds: int = 86400,
    ) -> None:
        self.redis_url = redis_url
        self.metrics_enabled = metrics_enabled
        self.default_metrics_ttl_seconds = default_metrics_ttl_seconds
        self.client: Redis | None = None

    async def connect(self) -> None:
        self.client = Redis.from_url(self.redis_url, decode_responses=True)
        await self.client.ping()

    def _client(self) -> Redis:
        if self.client is None:
            raise RuntimeError("Redis client has not been connected")
        return self.client

    async def get_json(self, key: str) -> dict[str, Any] | None:
        raw = await self._client().get(key)
        return json.loads(raw) if raw else None

    async def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        await self._client().set(key, json.dumps(value), ex=ttl_seconds)

    async def increment_with_ttl(self, key: str, ttl_seconds: int) -> int:
        pipe = self._client().pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = await pipe.execute()
        if ttl == -1:
            await self._client().expire(key, ttl_seconds)
        return int(count)

    async def increment_metric(
        self,
        name: str,
        tags: Mapping[str, Any] | None = None,
        ttl_seconds: int | None = None,
    ) -> int:
        if not self.metrics_enabled:
            return 0
        safe_tags = {str(key): str(value) for key, value in sorted((tags or {}).items())}
        tags_json = json.dumps(safe_tags, sort_keys=True, separators=(",", ":"))
        key = f"metrics:{name}:{sha256_hash(tags_json)}"
        return await self.increment_with_ttl(key, ttl_seconds=ttl_seconds or self.default_metrics_ttl_seconds)

    async def close(self) -> None:
        if self.client is not None:
            await self.client.aclose()
