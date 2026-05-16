import datetime

import pytest

from app.models.correlation import HistoricalRiskSnapshot, IOCActivitySummary, IOCProviderCorrelation, IOCTrend
from app.models.ioc import IOCRecord
from app.repositories.database import Database
from app.repositories.jobs_repository import JobsRepository
from app.services.ioc_aging_service import IOCAgingService


@pytest.mark.asyncio
async def test_jobs_repository() -> None:
    db = Database(":memory:")
    await db.init()
    repo = JobsRepository(db)

    # Test enqueue
    job_id = await repo.enqueue_job("deferred_enrichment", {"foo": "bar"}, delay_seconds=0)
    assert job_id > 0

    # Test fetch ready
    jobs = await repo.fetch_ready_jobs(10)
    assert len(jobs) == 1
    assert jobs[0].id == job_id
    assert jobs[0].payload["foo"] == "bar"

    # Fetch again, should be 0 because it's marked as 'processing' with a future next_run_at
    jobs2 = await repo.fetch_ready_jobs(10)
    assert len(jobs2) == 0

    # Mark completed
    await repo.mark_completed(job_id)

    # Mark failed
    job_id_2 = await repo.enqueue_job("deferred_enrichment", {"retry": True}, delay_seconds=0)
    jobs3 = await repo.fetch_ready_jobs(10)
    assert len(jobs3) == 1
    await repo.mark_failed(job_id_2, retry_delay_seconds=-10) # negative to force ready immediately

    jobs4 = await repo.fetch_ready_jobs(10)
    assert len(jobs4) == 1
    assert jobs4[0].retry_count == 1

    await db.close()


def test_ioc_aging_service() -> None:
    aging = IOCAgingService()

    past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=35)).strftime("%Y-%m-%d %H:%M:%S")

    ioc = IOCRecord(
        id=1,
        indicator_type="url",
        indicator_value="example.com",
        first_seen_at=past_date,
        last_seen_at=past_date,
        total_observations=1,
        cumulative_risk_score=50,
    )
    snapshot = HistoricalRiskSnapshot(average_risk=50, peak_risk=50, first_seen=past_date, last_seen=past_date)
    context = IOCActivitySummary(
        ioc=ioc, recent_observations=[], trend=IOCTrend("stable", 0.0), provider_correlation=IOCProviderCorrelation(1.0, "High"), risk_snapshot=snapshot
    )

    base_confidence = 80
    decayed = aging.calculate_decayed_confidence(base_confidence, context)

    assert decayed == 75  # 35 days = 1 decay interval of 5 points
