from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.repositories.analytics import AnalyticsRepository
from app.repositories.database import Database
from app.repositories.history import HistoryRepository
from app.repositories.users import UserRepository
from app.services.username_analyzer import UsernameAnalyzer
from app.utils.security import html_escape, sha256_hash

router = Router(name="username")


@router.message(Command("username"))
async def username_check(message: Message, settings: Settings, database: Database, sanitized_text: str) -> None:
    if not message.from_user:
        return
    await UserRepository(database, settings.admin_ids).upsert_from_telegram(message.from_user)

    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /username @example")
        return

    try:
        result = UsernameAnalyzer().analyze(parts[1])
    except ValueError as exc:
        await message.answer(html_escape(str(exc)))
        return

    lines = [
        "<b>Telegram Username Analysis</b>",
        f"Username: {html_escape(result.username)}",
        f"Risk: {html_escape(result.risk_level)} ({result.score}/100)",
        "",
        "<b>Signals</b>",
        *[f"- {html_escape(item)}" for item in result.signals],
        "",
        "<b>Recommendations</b>",
        *[f"- {html_escape(item)}" for item in result.recommendations],
    ]

    await HistoryRepository(database).add(
        message.from_user.id,
        "/username",
        f"{result.username} risk={result.risk_level}",
        input_hash=sha256_hash(result.username.lower()),
        threat_level=result.risk_level,
    )
    await AnalyticsRepository(database).track("username_analysis", message.from_user.id, {"risk": result.risk_level})
    await message.answer("\n".join(lines))

