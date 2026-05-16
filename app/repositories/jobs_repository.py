from __future__ import annotations

import json
import logging

from app.models.lifecycle import BackgroundTask
from app.repositories.database import Database

logger = logging.getLogger(__name__)


class JobsRepository:
    """Repository for managing persistent background tasks in SQLite."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def enqueue_job(self, task_type: str, payload: dict, delay_seconds: int = 0) -> int:
        query = f"""
            INSERT INTO background_jobs (task_type, payload, next_run_at)
            VALUES (?, ?, datetime('now', '+{delay_seconds} seconds'))
            RETURNING id;
        """
        async with self.db.conn().execute(query, (task_type, json.dumps(payload))) as cursor:
            row = await cursor.fetchone()
            if not row:
                raise RuntimeError("Failed to enqueue job")
            await self.db.conn().commit()
            return row["id"]

    async def fetch_ready_jobs(self, limit: int = 10) -> list[BackgroundTask]:
        query = """
            UPDATE background_jobs 
            SET status = 'processing', next_run_at = datetime('now', '+5 minutes')
            WHERE id IN (
                SELECT id FROM background_jobs 
                WHERE status IN ('pending', 'retrying') AND next_run_at <= CURRENT_TIMESTAMP
                ORDER BY next_run_at ASC LIMIT ?
            )
            RETURNING *;
        """
        results = []
        async with self.db.conn().execute(query, (limit,)) as cursor:
            async for row in cursor:
                results.append(
                    BackgroundTask(
                        id=row["id"],
                        task_type=row["task_type"],
                        payload=json.loads(row["payload"]),
                        status=row["status"],
                        next_run_at=row["next_run_at"],
                        retry_count=row["retry_count"],
                        created_at=row["created_at"],
                    )
                )
        await self.db.conn().commit()
        return results

    async def mark_completed(self, job_id: int) -> None:
        await self.db.conn().execute("UPDATE background_jobs SET status = 'completed' WHERE id = ?", (job_id,))
        await self.db.conn().commit()

    async def mark_failed(self, job_id: int, retry_delay_seconds: int, max_retries: int = 3) -> None:
        sign = "+" if retry_delay_seconds >= 0 else "-"
        abs_delay = abs(retry_delay_seconds)
        query = f"""
            UPDATE background_jobs 
            SET status = CASE WHEN retry_count >= {max_retries} THEN 'failed' ELSE 'retrying' END,
                retry_count = retry_count + 1,
                next_run_at = datetime('now', '{sign}{abs_delay} seconds')
            WHERE id = ?
        """
        await self.db.conn().execute(query, (job_id,))
        await self.db.conn().commit()
