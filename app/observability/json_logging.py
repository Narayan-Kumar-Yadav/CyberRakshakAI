from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.observability.context import get_correlation_id
from app.observability.redaction import redact_value

RESERVED_LOG_RECORD_KEYS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "message",
    "module",
    "msecs",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}


class JsonLogFormatter(logging.Formatter):
    """Minimal JSON formatter that redacts extras before serialization."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_value(record.getMessage()),
            "correlation_id": getattr(record, "correlation_id", None) or get_correlation_id(),
        }

        for key, value in record.__dict__.items():
            if key in RESERVED_LOG_RECORD_KEYS or key.startswith("_"):
                continue
            payload[key] = redact_value(value, key=key)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str)


def log_extra(event: str, **fields: Any) -> dict[str, Any]:
    return {"extra": {"event": event, **fields}}

