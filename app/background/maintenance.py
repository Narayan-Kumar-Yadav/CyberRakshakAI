import asyncio
import logging

from app.observability.metrics import increment_metric_safe
from app.repositories.database import Database
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class MaintenanceWorker:
    def __init__(self, db: Database, redis: RedisClient | None = None) -> None:
        self.db = db
        self.redis = redis
        self._running = False
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._running = True
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            await self._task

    async def _loop(self) -> None:
        logger.info("Maintenance worker started.")
        while self._running:
            try:
                # Sleep for 1 hour before running maintenance
                for _ in range(60 * 60):
                    if not self._running:
                        return
                    await asyncio.sleep(1)

                await self._prune_old_observations()
                await self._cleanup_failed_jobs()

                if self.redis:
                    await increment_metric_safe(self.redis, "maintenance_run_completed", {})

            except Exception:
                logger.exception("Error in maintenance worker loop")
                await asyncio.sleep(60)

    async def _prune_old_observations(self) -> None:
        # Prune threat observations older than 90 days to save space
        query = "DELETE FROM threat_observations WHERE created_at < datetime('now', '-90 days')"
        async with self.db.conn().execute(query) as cursor:
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Pruned {deleted} old threat observations.")
        await self.db.conn().commit()

    async def _cleanup_failed_jobs(self) -> None:
        # Prune background jobs that failed more than 7 days ago
        query = "DELETE FROM background_jobs WHERE status = 'failed' AND next_run_at < datetime('now', '-7 days')"
        async with self.db.conn().execute(query) as cursor:
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Pruned {deleted} old failed background jobs.")
        await self.db.conn().commit()
