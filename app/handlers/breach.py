from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.repositories.analytics import AnalyticsRepository
from app.repositories.database import Database
from app.repositories.history import HistoryRepository
from app.repositories.users import UserRepository
from app.services.hibp import HIBPService
from app.services.http_client import HttpClient
from app.services.recommendations import breach_recommendations
from app.services.redis_cache import RedisClient
from app.utils.security import html_escape, sha256_hash

router = Router(name="breach")


@router.message(Command("breach"))
async def breach_check(
    message: Message,
    settings: Settings,
    database: Database,
    redis: RedisClient,
    http_client: HttpClient,
    sanitized_text: str,
) -> None:
    if not message.from_user:
        return
    await UserRepository(database, settings.admin_ids).upsert_from_telegram(message.from_user)

    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /breach email@example.com")
        return

    email = parts[1].strip()
    service = HIBPService(settings, http_client, redis)
    try:
        summary = await service.check_email(email)
    except (RuntimeError, ValueError) as exc:
        await message.answer(html_escape(str(exc)))
        return

    status = "found in known breaches" if summary.breached else "not found in known breaches"
    cache_note = " cached" if summary.cached else ""
    lines = [
        "<b>Breach Check</b>",
        f"Status: {html_escape(status)}{cache_note}",
        f"Known breach count: {summary.breach_count}",
    ]
    if summary.names:
        lines.append("Breaches: " + html_escape(", ".join(summary.names)))
    lines.append("")
    lines.append("<b>Recommendations</b>")
    lines.extend(f"- {html_escape(item)}" for item in breach_recommendations(summary.breached))

    input_hash = sha256_hash(email.lower())
    await HistoryRepository(database).add(
        message.from_user.id,
        "/breach",
        f"Email {status}; count={summary.breach_count}",
        input_hash=input_hash,
        threat_level="High" if summary.breached else "Low",
    )
    await AnalyticsRepository(database).track("breach_check", message.from_user.id, {"breached": summary.breached})
    await message.answer("\n".join(lines))

