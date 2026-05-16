from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.repositories.database import Database
from app.repositories.fingerprint_repository import FingerprintRepository
from app.repositories.ioc_repository import IOCRepository
from app.utils.security import html_escape

router = Router(name="attribution")


@router.message(Command("fingerprint_lookup"))
async def fingerprint_lookup(message: Message, database: Database, sanitized_text: str) -> None:
    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /fingerprint_lookup <indicator>")
        return

    indicator = parts[1].strip().lower()
    fp_repo = FingerprintRepository(database)

    query = "SELECT id, indicator_type FROM iocs WHERE indicator_value = ? LIMIT 1"
    async with database.conn().execute(query, (indicator,)) as cursor:
        row = await cursor.fetchone()
        if not row:
            await message.answer("No fingerprint found for that indicator.")
            return
        ioc_id = row["id"]

    fp = await fp_repo.get_fingerprint(ioc_id)
    if not fp:
        await message.answer(f"No behavioral fingerprint stored for {html_escape(indicator)}.")
        return

    lines = [
        f"<b>Fingerprint for {html_escape(indicator)}</b>",
        f"- Redirect Hash: {fp.redirect_chain_hash or 'N/A'}",
        f"- Hosting ASN: {fp.hosting_asn or 'N/A'}",
        f"- Metadata Hash: {fp.metadata_hash or 'N/A'}",
    ]
    await message.answer("\n".join(lines))


@router.message(Command("threat_family"))
async def threat_family(message: Message, database: Database, settings: Settings, sanitized_text: str) -> None:
    """Admin only: list indicators attributed to this family."""
    if not message.from_user or message.from_user.id not in settings.admin_ids:
        return

    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /threat_family <family_name>")
        return

    family_name = parts[1].strip()

    query = "SELECT id, description FROM threat_families WHERE name = ?"
    async with database.conn().execute(query, (family_name,)) as cursor:
        row = await cursor.fetchone()
        if not row:
            await message.answer(f"Threat family '{html_escape(family_name)}' not found.")
            return
        family_id = row["id"]
        description = row["description"]

    # fetch IOCs
    query = """
        SELECT i.indicator_type, i.indicator_value, a.confidence, a.similarity_score
        FROM ioc_attributions a
        JOIN iocs i ON a.ioc_id = i.id
        WHERE a.family_id = ?
        ORDER BY a.confidence DESC LIMIT 20
    """
    lines = [f"<b>Threat Family: {html_escape(family_name)}</b>", f"<i>{html_escape(description)}</i>", ""]
    async with database.conn().execute(query, (family_id,)) as cursor:
        async for row in cursor:
            lines.append(
                f"- {html_escape(row['indicator_value'])} (Confidence: {row['confidence']}%, Similarity: {row['similarity_score']})"
            )

    if len(lines) == 3:
        lines.append("No active IOCs attributed.")

    await message.answer("\n".join(lines))
