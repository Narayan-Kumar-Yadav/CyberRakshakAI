from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "password",
    "passwd",
    "private_key",
    "secret",
    "seed",
    "seed_phrase",
    "session",
    "token",
    "x-goog-api-key",
    "x-apikey",
}

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|session)\s*[:=]\s*[A-Za-z0-9_\-\.]{8,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{12,}"),
    re.compile(r"(?i)\b(seed phrase|private key)\s*[:=]\s*.+"),
    re.compile(r"\b\d{6}\b"),
    re.compile(r"(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}"),
]

MAX_LOG_STRING_LENGTH = 300


def redact_text(value: str, max_length: int = MAX_LOG_STRING_LENGTH) -> str:
    redacted = value.replace("\x00", "")
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    if len(redacted) > max_length:
        redacted = f"{redacted[:max_length]}...[TRUNCATED]"
    return redacted


def redact_url(value: str) -> str:
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return redact_text(value)

    safe_query = []
    for key, item_value in parse_qsl(parts.query, keep_blank_values=True):
        if _is_sensitive_key(key):
            safe_query.append((key, "[REDACTED]"))
        else:
            safe_query.append((key, redact_text(item_value, max_length=60)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(safe_query), ""))


def redact_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): redact_value(value, key=str(key)) for key, value in values.items()}


def redact_value(value: Any, key: str | None = None) -> Any:
    if key and _is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, str):
        if value.startswith(("http://", "https://")):
            return redact_url(value)
        return redact_text(value)
    if isinstance(value, Mapping):
        return redact_mapping(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value[:20]]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value[:20])
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value))


def hash_identifier(value: int | str) -> str:
    from app.utils.security import sha256_hash

    return sha256_hash(str(value))[:16]


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in SENSITIVE_KEYS or any(item in normalized for item in SENSITIVE_KEYS)

