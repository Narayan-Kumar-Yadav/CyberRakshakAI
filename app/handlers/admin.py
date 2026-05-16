from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.repositories.analytics import AnalyticsRepository
from app.repositories.database import Database
from app.repositories.users import UserRepository
from app.utils.security import html_escape

router = Router(name="admin")


@router.message(Command("admin"))
async def admin_panel(message: Message, settings: Settings, database: Database) -> None:
    if not message.from_user:
        return

    users = UserRepository(database, settings.admin_ids)
    await users.upsert_from_telegram(message.from_user)
    if not await users.is_admin(message.from_user.id):
        await message.answer("Admin access denied.")
        return

    summary = await AnalyticsRepository(database).summary()
    lines = ["<b>Admin Analytics</b>"]
    for key, count in summary.items():
        lines.append(f"{html_escape(key)}: {count}")
    await message.answer("\n".join(lines))

