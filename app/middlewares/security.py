from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

from app.config import Settings
from app.observability.json_logging import log_extra
from app.observability.redaction import hash_identifier
from app.services.redis_cache import RedisClient
from app.utils.security import fingerprint_text, sanitize_text

logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseMiddleware):
    """Sanitizes inbound text and applies lightweight anti-spam checks."""

    def __init__(self, settings: Settings, redis: RedisClient) -> None:
        self.settings = settings
        self.redis = redis

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if not isinstance(event, Message) or event.text is None:
            return await handler(event, data)

        if len(event.text) > self.settings.text_max_length:
            await event.answer("That message is too long to analyze safely. Please send a shorter sample.")
            return None

        sanitized = sanitize_text(event.text, self.settings.text_max_length)
        data["sanitized_text"] = sanitized

        user_id = event.from_user.id if event.from_user else 0
        fingerprint = fingerprint_text(sanitized)
        spam_key = f"spam:{user_id}:{fingerprint}"
        repeats = await self.redis.increment_with_ttl(spam_key, ttl_seconds=30)
        if repeats > 4:
            logger.warning(
                "Repeated message blocked",
                **log_extra("security.spam_blocked", telegram_user_id_hash=hash_identifier(user_id)),
            )
            await event.answer("Please slow down. Repeated messages are temporarily blocked.")
            return None

        return await handler(event, data)
