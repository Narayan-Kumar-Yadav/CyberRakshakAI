from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.repositories.database import Database
from app.repositories.ioc_repository import IOCRepository
from app.repositories.relationship_repository import RelationshipRepository
from app.utils.security import html_escape

router = Router(name="graph")


@router.message(Command("related_iocs"))
async def related_iocs(message: Message, database: Database, sanitized_text: str) -> None:
    """Show 1st-degree relationship connections."""
    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /related_iocs <indicator>")
        return

    indicator = parts[1].strip().lower()
    rel_repo = RelationshipRepository(database)

    query = "SELECT id, indicator_type FROM iocs WHERE indicator_value = ? LIMIT 1"
    async with database.conn().execute(query, (indicator,)) as cursor:
        row = await cursor.fetchone()
        if not row:
            await message.answer("No graph relationships found for that indicator.")
            return
        ioc_id = row["id"]

    related = await rel_repo.get_related_iocs(ioc_id)
    if not related:
        await message.answer(f"No known infrastructure links for {html_escape(indicator)}.")
        return

    lines = [f"<b>Infrastructure Links for {html_escape(indicator)}</b>"]
    for rel in related:
        lines.append(
            f"- {html_escape(rel.relationship_type.value)}: {html_escape(rel.indicator_value)} ({rel.indicator_type}) [Risk {rel.cumulative_risk_score}]"
        )

    await message.answer("\n".join(lines))


@router.message(Command("campaign_lookup"))
async def campaign_lookup(message: Message, database: Database, settings: Settings, sanitized_text: str) -> None:
    """Admin only: identify if an indicator belongs to a wider campaign cluster."""
    if not message.from_user or message.from_user.id not in settings.admin_ids:
        return

    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /campaign_lookup <indicator>")
        return

    indicator = parts[1].strip().lower()
    rel_repo = RelationshipRepository(database)

    query = "SELECT id FROM iocs WHERE indicator_value = ? LIMIT 1"
    async with database.conn().execute(query, (indicator,)) as cursor:
        row = await cursor.fetchone()
        if not row:
            await message.answer("Indicator not found.")
            return
        ioc_id = row["id"]

    cluster = await rel_repo.get_campaign_cluster(ioc_id, max_depth=3)
    if not cluster.nodes:
        await message.answer("No broader campaign clusters detected.")
        return

    lines = [
        f"<b>Campaign Cluster Detected</b>",
        f"Nodes: {len(cluster.nodes)}",
        f"Max Risk: {cluster.max_risk}/100",
        f"Average Risk: {cluster.average_risk}/100",
        "",
    ]
    for node in cluster.nodes:
        lines.append(f"- {html_escape(node.indicator_value)} (Risk {node.cumulative_risk_score})")

    await message.answer("\n".join(lines))
