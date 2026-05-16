from __future__ import annotations

import logging

from app.config import Settings
from app.observability.json_logging import log_extra

logger = logging.getLogger(__name__)


REQUIRED_SECRET_FIELDS = ("bot_token",)
PLACEHOLDER_VALUES = {
    "",
    "change_me",
    "replace_me",
    "replace_with_telegram_bot_token",
    "replace_with_your_telegram_bot_token",
    "your_token_here",
}


def validate_startup_secrets(settings: Settings) -> None:
    """Fail fast for required secrets and warn safely for optional providers."""

    missing = [
        field
        for field in REQUIRED_SECRET_FIELDS
        if _is_missing_or_placeholder(getattr(settings, field, None))
    ]
    if missing:
        logger.critical(
            "Required startup secrets are missing",
            **log_extra("startup.secrets.missing", missing_fields=missing),
        )
        raise RuntimeError("Required startup secrets are missing. Check your environment configuration.")

    optional_provider_keys = {
        "virustotal": settings.virustotal_api_key,
        "abuseipdb": settings.abuseipdb_api_key,
        "urlscan": settings.urlscan_api_key,
        "gemini": settings.gemini_api_key,
    }
    for provider, secret in optional_provider_keys.items():
        if provider in settings.enabled_providers and _is_missing_or_placeholder(secret):
            logger.warning(
                "Optional provider secret is missing; provider will degrade safely",
                **log_extra("startup.provider_secret.missing", provider=provider),
            )


def _is_missing_or_placeholder(value: object) -> bool:
    if value is None:
        return True
    normalized = str(value).strip()
    return normalized.lower() in PLACEHOLDER_VALUES
