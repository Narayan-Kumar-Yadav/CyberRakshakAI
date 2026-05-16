from __future__ import annotations

import json
from typing import Any

from app.repositories.database import Database


class AnalyticsRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    async def track(self, event_name: str, telegram_id: int | None = None, metadata: dict[str, Any] | None = None) -> None:
        await self.database.conn().execute(
            "INSERT INTO analytics_events (telegram_id, event_name, metadata) VALUES (?, ?, ?)",
            (telegram_id, event_name, json.dumps(metadata or {})),
        )
        await self.database.conn().commit()

    async def summary(self) -> dict[str, int]:
        cursor = await self.database.conn().execute(
            """
            SELECT event_name, COUNT(*) AS count
            FROM analytics_events
            GROUP BY event_name
            ORDER BY count DESC
            """
        )
        rows = await cursor.fetchall()

        users_cursor = await self.database.conn().execute("SELECT COUNT(*) AS count FROM users")
        users_row = await users_cursor.fetchone()
        data = {row["event_name"]: int(row["count"]) for row in rows}
        data["registered_users"] = int(users_row["count"]) if users_row else 0
        return data

