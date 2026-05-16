from __future__ import annotations

import asyncio
import logging

from app.bot import create_dispatcher, run_bot
from app.config import get_settings
from app.logging_config import configure_logging
from app.repositories.database import Database
from app.security.startup_validation import validate_startup_secrets
from app.services.http_client import HttpClient
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    validate_startup_secrets(settings)

    database = Database(settings.database_path)
    redis = RedisClient(
        settings.redis_url,
        metrics_enabled=settings.enable_redis_metrics,
        default_metrics_ttl_seconds=settings.metrics_ttl_seconds,
    )
    http_client = HttpClient()

    await database.init()
    await redis.connect()
    await http_client.start()

    dispatcher, bot = create_dispatcher(settings, database, redis, http_client)

    try:
        logger.info("Starting %s in %s mode", settings.bot_name, settings.environment)
        await run_bot(bot, dispatcher)
    finally:
        await http_client.close()
        await redis.close()
        await database.close()


if __name__ == "__main__":
    asyncio.run(main())
