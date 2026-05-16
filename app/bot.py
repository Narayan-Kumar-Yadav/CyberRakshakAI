from __future__ import annotations

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

from app.config import Settings
from app.handlers import admin, assistant, breach, common, username, intelligence, graph, attribution, streaming
from app.middlewares.correlation import CorrelationMiddleware
from app.middlewares.rate_limit import RateLimitMiddleware
from app.middlewares.security import SecurityMiddleware
from app.repositories.database import Database
from app.services.http_client import HttpClient
from app.services.redis_cache import RedisClient


def create_dispatcher(
    settings: Settings,
    database: Database,
    redis: RedisClient,
    http_client: HttpClient,
) -> tuple[Dispatcher, Bot]:
    bot = Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dispatcher = Dispatcher(
        settings=settings,
        database=database,
        redis=redis,
        http_client=http_client,
    )

    dispatcher.message.middleware(CorrelationMiddleware())
    dispatcher.message.middleware(SecurityMiddleware(settings, redis))
    dispatcher.message.middleware(RateLimitMiddleware(settings, redis))

    dispatcher.include_router(common.router)
    dispatcher.include_router(breach.router)
    dispatcher.include_router(username.router)
    dispatcher.include_router(assistant.router)
    dispatcher.include_router(admin.router)
    dispatcher.include_router(intelligence.router)
    dispatcher.include_router(graph.router)
    dispatcher.include_router(attribution.router)
    dispatcher.include_router(streaming.router)
    return dispatcher, bot


async def run_bot(bot: Bot, dispatcher: Dispatcher) -> None:
    await dispatcher.start_polling(bot, allowed_updates=dispatcher.resolve_used_update_types())
