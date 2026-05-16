from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.keyboards.main import main_keyboard
from app.repositories.analytics import AnalyticsRepository
from app.repositories.database import Database
from app.repositories.history import HistoryRepository
from app.repositories.users import UserRepository
from app.utils.security import html_escape

router = Router(name="common")


@router.message(Command("start"))
async def start(message: Message, settings: Settings, database: Database) -> None:
    if message.from_user:
        await UserRepository(database, settings.admin_ids).upsert_from_telegram(message.from_user)
        await AnalyticsRepository(database).track("start", message.from_user.id)

    await message.answer(
        (
            f"<b>{html_escape(settings.bot_name)}</b>\n"
            "Your defensive cybersecurity assistant for breach checks, scam analysis, and safer account habits.\n\n"
            "Never send passwords, OTPs, seed phrases, private keys, or session tokens."
        ),
        reply_markup=main_keyboard(),
    )


@router.message(Command("help"))
async def help_command(message: Message) -> None:
    await message.answer(
        "\n".join(
            [
                "<b>Commands</b>",
                "/breach email@example.com - high-level breach exposure check",
                "/username @name - Telegram username risk analysis",
                "/scan suspicious text or URL - phishing/scam detection",
                "/analyze URL, IP, domain, or message - threat-intelligence report",
                "/ask your question - AI cybersecurity assistant",
                "/history - your recent safe activity summaries",
                "/ioc_history <indicator> - historical threat observations",
                "/related_iocs <indicator> - graph infrastructure connections",
                "/fingerprint_lookup <indicator> - behavioral hashes",
                "/stream_status - live ingestion metrics",
                "/recent_iocs - newly ingested threats",
                "/admin - restricted analytics",
            ]
        )
    )


@router.message(Command("history"))
async def history(message: Message, database: Database) -> None:
    if not message.from_user:
        return
    rows = await HistoryRepository(database).recent_for_user(message.from_user.id)
    if not rows:
        await message.answer("No history yet.")
        return

    lines = ["<b>Recent activity</b>"]
    for row in rows:
        level = f" [{html_escape(row['threat_level'])}]" if row.get("threat_level") else ""
        lines.append(f"{html_escape(row['created_at'])} - {html_escape(row['command'])}{level}: {html_escape(row['summary'])}")
    await message.answer("\n".join(lines))
