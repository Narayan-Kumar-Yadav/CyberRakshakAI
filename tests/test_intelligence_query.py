import pytest

from app.repositories.database import Database
from app.repositories.ioc_repository import IOCRepository
from app.services.intelligence_query_service import IntelligenceQueryService


@pytest.mark.asyncio
async def test_intelligence_query_service() -> None:
    db = Database(":memory:")
    await db.init()
    repo = IOCRepository(db)
    service = IntelligenceQueryService(repo)

    # Test empty state
    summary = await service.get_ioc_summary("url", "example.com")
    assert summary is None

    # Add single observation
    ioc_id = await repo.upsert_ioc("url", "example.com", 50)
    await repo.record_observation(
        ioc_id, provider_hits=1, risk_score=50, confidence_score=70, confidence_level="Moderate"
    )

    summary1 = await service.get_ioc_summary("url", "example.com")
    assert summary1 is not None
    assert summary1.trend.direction == "insufficient_data"

    # Add second observation indicating increasing risk
    await repo.record_observation(
        ioc_id, provider_hits=2, risk_score=60, confidence_score=80, confidence_level="High"
    )

    # Add third observation indicating increasing risk further
    await repo.record_observation(
        ioc_id, provider_hits=3, risk_score=85, confidence_score=90, confidence_level="High"
    )

    summary2 = await service.get_ioc_summary("url", "example.com")
    assert summary2 is not None
    assert len(summary2.recent_observations) == 3
    
    # Half 1 avg: 50
    # Half 2 avg: (60 + 85) / 2 = 72.5
    # diff = 22.5 -> increasing
    assert summary2.trend.direction == "increasing"

    # Agreement score for High (2 out of 3 = 0.67)
    assert summary2.provider_correlation.most_frequent_confidence_level == "High"
    assert summary2.provider_correlation.agreement_score == 0.67

    await db.close()
