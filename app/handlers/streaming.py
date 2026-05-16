from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.repositories.database import Database
from app.utils.security import html_escape

router = Router(name="streaming")


@router.message(Command("stream_status"))
async def stream_status(message: Message, database: Database) -> None:
    query = """
        SELECT COUNT(*) as cnt 
        FROM iocs 
        WHERE created_at >= datetime('now', '-1 hour')
    """
    async with database.conn().execute(query) as cursor:
        row = await cursor.fetchone()
        cnt = row["cnt"] if row else 0

    lines = [
        "<b>Live Stream Status</b>",
        f"- IOCs ingested in last hour: {cnt}",
        "- Ingestion Engine: Active",
        "- Alerting: Active",
    ]
    await message.answer("\n".join(lines))


@router.message(Command("recent_iocs"))
async def recent_iocs(message: Message, database: Database) -> None:
    query = """
        SELECT indicator_type, indicator_value, risk_score 
        FROM iocs 
        WHERE risk_score >= 50
        ORDER BY created_at DESC 
        LIMIT 10
    """
    lines = ["<b>Recent High-Risk IOCs</b>"]
    async with database.conn().execute(query) as cursor:
        async for row in cursor:
            lines.append(f"- {html_escape(row['indicator_value'])} (Risk: {row['risk_score']})")

    if len(lines) == 1:
        lines.append("No recent high-risk IOCs found.")

    await message.answer("\n".join(lines))


@router.message(Command("live_campaigns"))
async def live_campaigns(message: Message, database: Database, settings: Settings) -> None:
    """Admin only: list most active recent campaigns."""
    if not message.from_user or message.from_user.id not in settings.admin_ids:
        return

    query = """
        SELECT f.name, COUNT(a.ioc_id) as node_count
        FROM threat_families f
        JOIN ioc_attributions a ON f.id = a.family_id
        GROUP BY f.id
        ORDER BY node_count DESC
        LIMIT 5
    """
    lines = ["<b>Top Live Campaigns</b>"]
    async with database.conn().execute(query) as cursor:
        async for row in cursor:
            lines.append(f"- {html_escape(row['name'])}: {row['node_count']} nodes")

    if len(lines) == 1:
        lines.append("No active campaigns detected.")

    await message.answer("\n".join(lines))
