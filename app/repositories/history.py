from __future__ import annotations

from app.repositories.database import Database


class HistoryRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    async def add(
        self,
        telegram_id: int,
        command: str,
        summary: str,
        input_hash: str | None = None,
        threat_level: str | None = None,
    ) -> None:
        await self.database.conn().execute(
            """
            INSERT INTO history (telegram_id, command, input_hash, threat_level, summary)
            VALUES (?, ?, ?, ?, ?)
            """,
            (telegram_id, command, input_hash, threat_level, summary[:500]),
        )
        await self.database.conn().commit()

    async def recent_for_user(self, telegram_id: int, limit: int = 5) -> list[dict[str, str]]:
        cursor = await self.database.conn().execute(
            """
            SELECT command, threat_level, summary, created_at
            FROM history
            WHERE telegram_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (telegram_id, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

