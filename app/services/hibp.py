from __future__ import annotations

import logging
from dataclasses import dataclass
from email_validator import EmailNotValidError, validate_email

from app.config import Settings
from app.observability.json_logging import log_extra
from app.services.http_client import HttpClient
from app.services.redis_cache import RedisClient
from app.utils.security import sha256_hash

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BreachSummary:
    breached: bool
    breach_count: int
    names: list[str]
    cached: bool = False


class HIBPService:
    """HaveIBeenPwned integration that caches only safe, summarized results."""

    def __init__(self, settings: Settings, http_client: HttpClient, redis: RedisClient) -> None:
        self.settings = settings
        self.http_client = http_client
        self.redis = redis

    async def check_email(self, email: str) -> BreachSummary:
        try:
            normalized = validate_email(email, check_deliverability=False).normalized.lower()
        except EmailNotValidError as exc:
            raise ValueError("Please provide a valid email address.") from exc

        cache_key = f"hibp:{sha256_hash(normalized)}"
        cached = await self.redis.get_json(cache_key)
        if cached:
            return BreachSummary(
                breached=bool(cached["breached"]),
                breach_count=int(cached["breach_count"]),
                names=list(cached["names"]),
                cached=True,
            )

        if not self.settings.hibp_api_key:
            raise RuntimeError("HIBP_API_KEY is not configured.")

        session = self.http_client.get_session()
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{normalized}"
        headers = {
            "hibp-api-key": self.settings.hibp_api_key,
            "user-agent": self.settings.hibp_user_agent,
        }
        params = {"truncateResponse": "true"}

        async with session.get(url, headers=headers, params=params) as response:
            if response.status == 404:
                summary = BreachSummary(False, 0, [])
            elif response.status == 200:
                payload = await response.json()
                names = sorted({str(item.get("Name", "Unknown")) for item in payload if isinstance(item, dict)})
                summary = BreachSummary(True, len(names), names[:10])
            elif response.status == 429:
                raise RuntimeError("HaveIBeenPwned rate limit reached. Please try later.")
            else:
                logger.warning("HIBP request failed", **log_extra("provider.error_response", provider="hibp", status=response.status))
                raise RuntimeError("Breach service is temporarily unavailable.")

        await self.redis.set_json(
            cache_key,
            {"breached": summary.breached, "breach_count": summary.breach_count, "names": summary.names},
            ttl_seconds=60 * 60 * 12,
        )
        return summary
