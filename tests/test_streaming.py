from datetime import datetime

import pytest

from dataclasses import dataclass

from app.models.streaming import LiveThreatEvent
from app.repositories.database import Database
from app.repositories.ioc_repository import IOCRepository
from app.repositories.jobs_repository import JobsRepository
from app.streaming.alerting import AlertingService
from app.streaming.event_processor import EventProcessor


class MockBot:
    def __init__(self) -> None:
        self.sent_messages: list[tuple[int, str]] = []

    async def send_message(self, chat_id: int, text: str) -> None:
        self.sent_messages.append((chat_id, text))


@dataclass
class MockSettings:
    admin_ids: list[int]

@pytest.mark.asyncio
async def test_streaming_event_processor() -> None:
    db = Database(":memory:")
    await db.init()
    ioc_repo = IOCRepository(db)
    jobs_repo = JobsRepository(db)
    settings = MockSettings(admin_ids=[123])
    bot = MockBot()
    alerting = AlertingService(bot, settings)

    processor = EventProcessor(ioc_repo, jobs_repo, alerting, redis=None)

    event = LiveThreatEvent(
        event_id="evt_1",
        timestamp=datetime.now(),
        source_feed="mock_feed",
        indicator_type="domain",
        indicator_value="streaming-evil.com",
        risk_score=85,
        metadata={"asn": "AS999"},
    )

    update = await processor.process_event(event)

    assert update is not None
    assert update.is_new_ioc is True
    assert update.risk_escalated is True

    # Verify IOC was persisted
    ioc = await ioc_repo.get_ioc("domain", "streaming-evil.com")
    assert ioc is not None
    assert ioc.risk_score == 85

    # Verify background job was enqueued for correlation
    jobs = await jobs_repo.fetch_ready_jobs(10)
    assert len(jobs) == 1
    assert jobs[0].task_type == "correlate_relationships"

    # Verify alert was sent
    assert len(bot.sent_messages) == 1
    assert "Critical Risk Escalation" in bot.sent_messages[0][1]

    await db.close()
