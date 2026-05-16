from __future__ import annotations

from aiogram.types import User

from app.repositories.database import Database


class UserRepository:
    def __init__(self, database: Database, admin_ids: set[int]) -> None:
        self.database = database
        self.admin_ids = admin_ids

    async def upsert_from_telegram(self, user: User) -> None:
        await self.database.conn().execute(
            """
            INSERT INTO users (telegram_id, username, first_name, is_admin)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                username=excluded.username,
                first_name=excluded.first_name,
                is_admin=excluded.is_admin,
                last_seen_at=CURRENT_TIMESTAMP
            """,
            (user.id, user.username, user.first_name, int(user.id in self.admin_ids)),
        )
        await self.database.conn().commit()

    async def is_admin(self, telegram_id: int) -> bool:
        if telegram_id in self.admin_ids:
            return True
        cursor = await self.database.conn().execute(
            "SELECT is_admin FROM users WHERE telegram_id = ?",
            (telegram_id,),
        )
        row = await cursor.fetchone()
        return bool(row and row["is_admin"])

