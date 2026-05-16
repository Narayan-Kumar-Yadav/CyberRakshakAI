from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from time import perf_counter
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

from app.observability.context import new_correlation_id, reset_correlation_id, set_correlation_id
from app.observability.json_logging import log_extra
from app.observability.redaction import hash_identifier
from app.observability.timing import elapsed_ms

logger = logging.getLogger(__name__)


class CorrelationMiddleware(BaseMiddleware):
    """Creates one correlation ID per Telegram message and stores it in async context."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        correlation_id = new_correlation_id()
        token = set_correlation_id(correlation_id)
        data["correlation_id"] = correlation_id

        user_hash = None
        command = None
        if isinstance(event, Message):
            if event.from_user:
                user_hash = hash_identifier(event.from_user.id)
            command = event.text.split(maxsplit=1)[0] if event.text else None

        start = perf_counter()
        logger.info(
            "Telegram update started",
            **log_extra("telegram.update.started", command=command, telegram_user_id_hash=user_hash),
        )
        try:
            return await handler(event, data)
        except Exception:
            logger.exception(
                "Telegram update failed",
                **log_extra(
                    "telegram.update.failed",
                    command=command,
                    telegram_user_id_hash=user_hash,
                    duration_ms=elapsed_ms(start),
                ),
            )
            raise
        finally:
            logger.info(
                "Telegram update completed",
                **log_extra(
                    "telegram.update.completed",
                    command=command,
                    telegram_user_id_hash=user_hash,
                    duration_ms=elapsed_ms(start),
                ),
            )
            reset_correlation_id(token)

