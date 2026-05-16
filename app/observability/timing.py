from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from time import perf_counter
from typing import Any, AsyncIterator

from app.observability.json_logging import log_extra


def elapsed_ms(start: float) -> int:
    return int((perf_counter() - start) * 1000)


@asynccontextmanager
async def timed_operation(
    logger: logging.Logger,
    event_prefix: str,
    **fields: Any,
) -> AsyncIterator[dict[str, Any]]:
    start = perf_counter()
    logger.info("%s started", event_prefix, **log_extra(f"{event_prefix}.started", **fields))
    state: dict[str, Any] = {"start": start}
    try:
        yield state
    except Exception:
        duration = elapsed_ms(start)
        logger.exception(
            "%s failed",
            event_prefix,
            **log_extra(f"{event_prefix}.failed", duration_ms=duration, **fields),
        )
        raise
    else:
        duration = elapsed_ms(start)
        logger.info(
            "%s completed",
            event_prefix,
            **log_extra(f"{event_prefix}.completed", duration_ms=duration, **fields),
        )


def latency_bucket(duration_ms: int) -> str:
    if duration_ms < 100:
        return "lt_100ms"
    if duration_ms < 500:
        return "lt_500ms"
    if duration_ms < 1000:
        return "lt_1s"
    if duration_ms < 3000:
        return "lt_3s"
    return "gte_3s"

