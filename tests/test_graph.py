import pytest

from app.models.graph import RelationshipType
from app.repositories.database import Database
from app.repositories.ioc_repository import IOCRepository
from app.repositories.relationship_repository import RelationshipRepository


@pytest.mark.asyncio
async def test_relationship_graph() -> None:
    db = Database(":memory:")
    await db.init()
    ioc_repo = IOCRepository(db)
    rel_repo = RelationshipRepository(db)

    # Create IOCs
    source_id = await ioc_repo.upsert_ioc("domain", "evil.com", risk_score=70)
    target_id1 = await ioc_repo.upsert_ioc("ip", "1.1.1.1", risk_score=20)
    target_id2 = await ioc_repo.upsert_ioc("url", "http://evil.com/payload", risk_score=80)
    target_id3 = await ioc_repo.upsert_ioc("domain", "another-evil.com", risk_score=65)

    # Create relationships
    await rel_repo.upsert_relationship(source_id, target_id1, RelationshipType.RESOLVES_TO)
    await rel_repo.upsert_relationship(target_id2, source_id, RelationshipType.HOSTED_ON)

    # Query 1st degree neighborhood
    related = await rel_repo.get_related_iocs(source_id)
    assert len(related) == 2
    types = {r.relationship_type for r in related}
    assert RelationshipType.RESOLVES_TO in types
    assert RelationshipType.HOSTED_ON in types

    # Connect a third domain to the IP to form a campaign cluster
    await rel_repo.upsert_relationship(target_id3, target_id1, RelationshipType.RESOLVES_TO)

    # Fetch campaign cluster recursively
    cluster = await rel_repo.get_campaign_cluster(source_id)
    assert len(cluster.nodes) == 3  # The 3 others are in the cluster (source is the root)
    assert cluster.max_risk == 80  # from target_id2

    await db.close()
