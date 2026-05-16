import logging

from app.models.streaming import IntelligenceUpdate, LiveThreatEvent
from app.observability.metrics import increment_metric_safe
from app.repositories.ioc_repository import IOCRepository
from app.repositories.jobs_repository import JobsRepository
from app.services.redis_cache import RedisClient
from app.streaming.alerting import AlertingService

logger = logging.getLogger(__name__)


class EventProcessor:
    """Processes streaming events idempotently and propagates state changes."""

    def __init__(
        self,
        ioc_repo: IOCRepository,
        jobs_repo: JobsRepository,
        alerting: AlertingService,
        redis: RedisClient | None = None,
    ) -> None:
        self.ioc_repo = ioc_repo
        self.jobs_repo = jobs_repo
        self.alerting = alerting
        self.redis = redis

    async def process_event(self, event: LiveThreatEvent) -> IntelligenceUpdate | None:
        # Idempotent check to avoid duplicate ingestion
        if self.redis:
            key = f"processed_event:{event.event_id}"
            if await self.redis.get(key):
                await increment_metric_safe(self.redis, "duplicate_events_dropped", {})
                return None
            await self.redis.setex(key, 86400, "1")  # 24 hr deduplication window

        # Upsert IOC
        existing_ioc = await self.ioc_repo.get_ioc(event.indicator_type, event.indicator_value)
        is_new = existing_ioc is None
        previous_risk = existing_ioc.risk_score if existing_ioc else 0
        risk_escalated = event.risk_score > previous_risk

        new_risk = max(previous_risk, event.risk_score)
        ioc_id = await self.ioc_repo.upsert_ioc(event.indicator_type, event.indicator_value, new_risk)

        # Enqueue deferred correlation and fingerprinting so we don't block the stream
        provider_dict = {
            "source": event.source_feed,
            "indicator": {"type": event.indicator_type, "value": event.indicator_value},
            "status": "ok",
            "risk_score": event.risk_score,
            "risk_level": "high" if event.risk_score >= 70 else ("medium" if event.risk_score >= 40 else "low"),
            "malicious": event.risk_score >= 50,
            "suspicious": event.risk_score >= 30,
            "metadata": event.metadata,
        }

        await self.jobs_repo.enqueue_job(
            task_type="correlate_relationships",
            payload={
                "source_ioc_id": ioc_id,
                "indicator_type": event.indicator_type,
                "provider_results": [provider_dict],
            },
            delay_seconds=0,
        )

        update = IntelligenceUpdate(event, is_new, risk_escalated, previous_risk)

        if update.risk_escalated:
            await self.alerting.alert_critical_update(update)

        if self.redis:
            await increment_metric_safe(self.redis, "live_events_processed", {"source": event.source_feed})

        return update
