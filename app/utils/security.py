from __future__ import annotations

import hashlib
import html
import re

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(token|api[_-]?key|secret)\s*[:=]\s*[A-Za-z0-9_\-\.]{8,}"),
    re.compile(r"\b\d{6}\b"),
]


def sanitize_text(value: str, max_length: int = 4000) -> str:
    normalized = value.replace("\x00", "").strip()
    normalized = normalized[:max_length]
    for pattern in SECRET_PATTERNS:
        normalized = pattern.sub("[REDACTED_SECRET]", normalized)
    return normalized


def html_escape(value: str) -> str:
    return html.escape(value, quote=True)


def sha256_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fingerprint_text(value: str) -> str:
    compact = re.sub(r"\s+", " ", value.lower()).strip()
    return sha256_hash(compact)

