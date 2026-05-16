from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded only from environment variables and .env."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    bot_token: str = Field(..., alias="BOT_TOKEN")
    bot_name: str = Field(default="CyberRakshak.ai", alias="BOT_NAME")
    environment: Literal["development", "staging", "production"] = Field(default="development", alias="ENVIRONMENT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: Literal["json", "text"] = Field(default="json", alias="LOG_FORMAT")

    database_path: str = Field(default="/data/cyberrakshak.sqlite3", alias="DATABASE_PATH")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    hibp_api_key: str | None = Field(default=None, alias="HIBP_API_KEY")
    hibp_user_agent: str = Field(default="CyberRakshak.ai Security Bot", alias="HIBP_USER_AGENT")

    virustotal_api_key: str | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str | None = Field(default=None, alias="ABUSEIPDB_API_KEY")
    urlscan_api_key: str | None = Field(default=None, alias="URLSCAN_API_KEY")
    enabled_providers: set[str] | str = Field(
        default_factory=lambda: {"virustotal", "urlhaus", "abuseipdb", "urlscan"},
        alias="ENABLED_PROVIDERS",
    )
    provider_timeout_seconds: float = Field(default=8.0, alias="PROVIDER_TIMEOUT_SECONDS")
    urlscan_visibility: Literal["public", "unlisted", "private"] = Field(default="unlisted", alias="URLSCAN_VISIBILITY")
    urlscan_poll_attempts: int = Field(default=2, alias="URLSCAN_POLL_ATTEMPTS")
    urlscan_poll_delay_seconds: float = Field(default=2.0, alias="URLSCAN_POLL_DELAY_SECONDS")
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    gemini_api_base_url: str = Field(
        default="https://generativelanguage.googleapis.com/v1beta",
        alias="GEMINI_API_BASE_URL",
    )
    gemini_model: str = Field(default="gemini-2.5-flash", alias="GEMINI_MODEL")

    admin_ids: set[int] | str = Field(default_factory=set, alias="ADMIN_IDS")
    default_rate_limit: int = Field(default=12, alias="DEFAULT_RATE_LIMIT")
    default_rate_window_seconds: int = Field(default=60, alias="DEFAULT_RATE_WINDOW_SECONDS")
    text_max_length: int = Field(default=4000, alias="TEXT_MAX_LENGTH")
    enable_redis_metrics: bool = Field(default=True, alias="ENABLE_REDIS_METRICS")
    metrics_ttl_seconds: int = Field(default=86400, alias="METRICS_TTL_SECONDS")

    @field_validator("admin_ids", mode="before")
    @classmethod
    def parse_admin_ids(cls, value: object) -> set[int]:
        if value in (None, ""):
            return set()
        if isinstance(value, set):
            return value
        if isinstance(value, int):
            return {value}
        if isinstance(value, str):
            return {int(item.strip()) for item in value.split(",") if item.strip()}
        raise ValueError("ADMIN_IDS must be a comma-separated list of Telegram user IDs")

    @field_validator("enabled_providers", mode="before")
    @classmethod
    def parse_enabled_providers(cls, value: object) -> set[str]:
        if value in (None, ""):
            return {"virustotal", "urlhaus", "abuseipdb", "urlscan"}
        if isinstance(value, set):
            return {str(item).strip().lower() for item in value if str(item).strip()}
        if isinstance(value, str):
            return {item.strip().lower() for item in value.split(",") if item.strip()}
        raise ValueError("ENABLED_PROVIDERS must be a comma-separated provider list")

    @model_validator(mode="after")
    def validate_runtime_configuration(self) -> "Settings":
        known_providers = {"virustotal", "urlhaus", "abuseipdb", "urlscan"}
        unknown = self.enabled_providers - known_providers
        if unknown:
            raise ValueError(f"Unknown providers in ENABLED_PROVIDERS: {', '.join(sorted(unknown))}")
        if not self.bot_token or self.bot_token.strip() in {
            "replace_with_telegram_bot_token",
            "replace_with_your_telegram_bot_token",
            "replace_me",
        }:
            raise ValueError("BOT_TOKEN is required and must not be a placeholder.")
        if self.provider_timeout_seconds <= 0:
            raise ValueError("PROVIDER_TIMEOUT_SECONDS must be greater than zero.")
        if self.metrics_ttl_seconds <= 0:
            raise ValueError("METRICS_TTL_SECONDS must be greater than zero.")
        if self.urlscan_poll_attempts < 0:
            raise ValueError("URLSCAN_POLL_ATTEMPTS must be zero or greater.")
        if self.urlscan_poll_delay_seconds < 0:
            raise ValueError("URLSCAN_POLL_DELAY_SECONDS must be zero or greater.")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
