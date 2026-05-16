import asyncio
import logging
from time import perf_counter

from app.background.handlers.correlation import CorrelationJobHandler
from app.background.handlers.enrichment import EnrichmentJobHandler
from app.background.handlers.streaming import FeedSyncJobHandler
from app.models.lifecycle import BackgroundTask
from app.observability.metrics import increment_metric_safe
from app.observability.timing import elapsed_ms
from app.repositories.jobs_repository import JobsRepository
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class AsyncWorker:
    def __init__(
        self,
        jobs_repo: JobsRepository,
        enrichment_handler: EnrichmentJobHandler,
        correlation_handler: CorrelationJobHandler | None = None,
        feed_sync_handler: FeedSyncJobHandler | None = None,
        redis: RedisClient | None = None,
    ) -> None:
        self.jobs_repo = jobs_repo
        self.enrichment_handler = enrichment_handler
        self.correlation_handler = correlation_handler
        self.feed_sync_handler = feed_sync_handler
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
        logger.info("Background worker started.")
        while self._running:
            try:
                jobs = await self.jobs_repo.fetch_ready_jobs(limit=10)
                if not jobs:
                    await asyncio.sleep(5)
                    continue

                if self.redis:
                    await increment_metric_safe(self.redis, "background_queue_depth", {"count": len(jobs)})

                tasks = [self._process_job(job) for job in jobs]
                await asyncio.gather(*tasks)
            except Exception:
                logger.exception("Error in background worker loop")
                await asyncio.sleep(5)

    async def _process_job(self, job: BackgroundTask) -> None:
        start = perf_counter()
        try:
            if job.task_type == "deferred_enrichment":
                await self.enrichment_handler.handle(job)
            elif job.task_type == "correlate_relationships" and self.correlation_handler:
                await self.correlation_handler.handle(job)
            elif job.task_type == "feed_sync" and self.feed_sync_handler:
                await self.feed_sync_handler.handle(job)
            else:
                logger.warning(f"Unknown or missing handler for task type: {job.task_type}")

            await self.jobs_repo.mark_completed(job.id)
            if self.redis:
                duration = elapsed_ms(start)
                await increment_metric_safe(self.redis, "background_task_latency", {"task_type": job.task_type, "ms": int(duration)})

        except Exception as e:
            logger.warning(f"Background task {job.id} failed: {e}")
            await self.jobs_repo.mark_failed(job.id, retry_delay_seconds=60)
            if self.redis:
                await increment_metric_safe(self.redis, "background_task_retried", {"task_type": job.task_type})
