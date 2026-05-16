import pytest

from app.repositories.database import Database
from app.repositories.ioc_repository import IOCRepository


@pytest.mark.asyncio
async def test_ioc_repository_upsert_and_record() -> None:
    db = Database(":memory:")
    await db.init()
    repo = IOCRepository(db)

    # Test initial upsert
    ioc_id1 = await repo.upsert_ioc("url", "example.com", 50)
    assert ioc_id1 == 1

    ioc = await repo.get_ioc("url", "example.com")
    assert ioc is not None
    assert ioc.indicator_type == "url"
    assert ioc.indicator_value == "example.com"
    assert ioc.total_observations == 1
    assert ioc.cumulative_risk_score == 50

    # Test second upsert (increments observation, updates risk if higher)
    ioc_id2 = await repo.upsert_ioc("url", "example.com", 75)
    assert ioc_id1 == ioc_id2

    ioc2 = await repo.get_ioc("url", "example.com")
    assert ioc2 is not None
    assert ioc2.total_observations == 2
    assert ioc2.cumulative_risk_score == 75

    # Test lower risk doesn't reduce cumulative
    await repo.upsert_ioc("url", "example.com", 20)
    ioc3 = await repo.get_ioc("url", "example.com")
    assert ioc3 is not None
    assert ioc3.total_observations == 3
    assert ioc3.cumulative_risk_score == 75

    # Record specific observation
    await repo.record_observation(ioc_id1, provider_hits=2, risk_score=75, confidence_score=80, confidence_level="High")

    async with db.conn().execute("SELECT * FROM threat_observations WHERE ioc_id = ?", (ioc_id1,)) as cursor:
        rows = await cursor.fetchall()
        assert len(rows) == 1
        assert rows[0]["provider_hits"] == 2
        assert rows[0]["risk_score"] == 75
        assert rows[0]["confidence_score"] == 80
        assert rows[0]["confidence_level"] == "High"

    await db.close()
