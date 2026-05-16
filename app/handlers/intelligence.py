from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.repositories.database import Database
from app.repositories.ioc_repository import IOCRepository
from app.services.intelligence_query_service import IntelligenceQueryService
from app.services.redis_cache import RedisClient
from app.utils.security import html_escape

router = Router(name="intelligence")


@router.message(Command("ioc_history"))
async def ioc_history(message: Message, database: Database, redis: RedisClient, sanitized_text: str) -> None:
    """Lookup historical observations for an indicator (public)."""
    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /ioc_history <url|domain|ip>")
        return

    # Basic parsing
    indicator = parts[1].strip().lower()
    
    # We infer type from simple rules or just query the DB for the exact value
    # For now, let's just query the DB for the value across types
    repo = IOCRepository(database)
    service = IntelligenceQueryService(repo, redis)
    
    # Attempt to find the IOC by value
    query = "SELECT indicator_type FROM iocs WHERE indicator_value = ? LIMIT 1"
    async with database.conn().execute(query, (indicator,)) as cursor:
        row = await cursor.fetchone()
        if not row:
            await message.answer("No historical intelligence found for that indicator.")
            return
        indicator_type = row["indicator_type"]

    summary = await service.get_ioc_summary(indicator_type, indicator)
    if not summary:
        await message.answer("No historical intelligence found for that indicator.")
        return

    lines = [
        f"<b>IOC History:</b> {html_escape(indicator)}",
        f"Type: {html_escape(indicator_type)}",
        f"First seen: {html_escape(summary.risk_snapshot.first_seen)}",
        f"Last seen: {html_escape(summary.risk_snapshot.last_seen)}",
        f"Total observations: {summary.ioc.total_observations}",
        f"Cumulative risk score: {summary.ioc.cumulative_risk_score}/100",
        "",
        "<b>Trends</b>",
        f"Risk Trend: {html_escape(summary.trend.direction.title())}",
        f"Peak Risk: {summary.risk_snapshot.peak_risk}/100",
        f"Provider Agreement: {int(summary.provider_correlation.agreement_score * 100)}%",
    ]
    await message.answer("\n".join(lines))


@router.message(Command("recent_threats"))
async def recent_threats(message: Message, database: Database, settings: Settings) -> None:
    """Admin only: View recent global threats."""
    if not message.from_user or message.from_user.id not in settings.admin_ids:
        return

    repo = IOCRepository(database)
    recent = await repo.get_recent_iocs(limit=10)

    if not recent:
        await message.answer("No recent threats recorded.")
        return

    lines = ["<b>Recent Global Threats</b>"]
    for ioc in recent:
        lines.append(f"- {html_escape(ioc.indicator_value)} ({html_escape(ioc.indicator_type)}) : Risk {ioc.cumulative_risk_score} [Observed {ioc.total_observations}x]")
    
    await message.answer("\n".join(lines))


@router.message(Command("ioc_stats"))
async def ioc_stats(message: Message, database: Database, settings: Settings) -> None:
    """Admin only: View highest risk recurring threats."""
    if not message.from_user or message.from_user.id not in settings.admin_ids:
        return

    repo = IOCRepository(database)
    repeated = await repo.get_repeated_iocs(min_observations=2, limit=10)

    if not repeated:
        await message.answer("No recurring threats recorded.")
        return

    lines = ["<b>Top Recurring Threats</b>"]
    for ioc in repeated:
        lines.append(f"- {html_escape(ioc.indicator_value)} ({html_escape(ioc.indicator_type)}) : Risk {ioc.cumulative_risk_score} [Observed {ioc.total_observations}x]")
    
    await message.answer("\n".join(lines))
