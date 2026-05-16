from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

from app.config import Settings
from app.services.redis_cache import RedisClient


class RateLimitMiddleware(BaseMiddleware):
    """Redis-backed per-user rate limiting for all message handlers."""

    def __init__(self, settings: Settings, redis: RedisClient) -> None:
        self.settings = settings
        self.redis = redis

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if not isinstance(event, Message) or event.from_user is None:
            return await handler(event, data)

        command = event.text.split(maxsplit=1)[0] if event.text else "message"
        key = f"rl:{event.from_user.id}:{command}"
        count = await self.redis.increment_with_ttl(key, ttl_seconds=self.settings.default_rate_window_seconds)

        if count > self.settings.default_rate_limit:
            await event.answer("Rate limit reached. Please wait a minute before trying again.")
            return None

        return await handler(event, data)

