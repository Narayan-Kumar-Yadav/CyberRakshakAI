import pytest

from app.models.api_results import Indicator, NormalizedThreatResult
from app.models.risk_level import RiskLevel
from app.repositories.database import Database
from app.repositories.fingerprint_repository import FingerprintRepository
from app.repositories.ioc_repository import IOCRepository
from app.services.fingerprinting import FingerprintingService


@pytest.mark.asyncio
async def test_fingerprinting_and_attribution() -> None:
    db = Database(":memory:")
    await db.init()
    ioc_repo = IOCRepository(db)
    fp_repo = FingerprintRepository(db)
    fp_service = FingerprintingService(fp_repo)

    # create 3 IOCs that share same ASN
    id1 = await ioc_repo.upsert_ioc("domain", "evil1.com", risk_score=80)
    id2 = await ioc_repo.upsert_ioc("domain", "evil2.com", risk_score=80)
    id3 = await ioc_repo.upsert_ioc("domain", "evil3.com", risk_score=80)

    # Provider results mock
    def get_pr(domain: str) -> list[NormalizedThreatResult]:
        return [
            NormalizedThreatResult(
                source="mock",
                indicator=Indicator(type="domain", value=domain),
                status="ok",
                risk_score=80,
                risk_level=RiskLevel.HIGH,
                metadata={"asn": "AS12345", "redirects_to": ["http://payload.com/drop"]},
            )
        ]

    # Generate for 1
    fp1 = await fp_service.generate_and_persist(id1, get_pr("evil1.com"))
    assert fp1.hosting_asn == "AS12345"
    assert fp1.redirect_chain_hash is not None
    await fp_service.calculate_similarity_and_attribute(fp1, 80)

    # Generate for 2
    fp2 = await fp_service.generate_and_persist(id2, get_pr("evil2.com"))
    await fp_service.calculate_similarity_and_attribute(fp2, 80)

    # Now there are 2 sharing same ASN and Hash, family should be auto-created
    attrs2 = await fp_repo.get_attributions(id2)
    assert len(attrs2) == 1
    assert "Campaign" in attrs2[0].family.name

    # Generate for 3
    fp3 = await fp_service.generate_and_persist(id3, get_pr("evil3.com"))
    await fp_service.calculate_similarity_and_attribute(fp3, 80)

    attrs3 = await fp_repo.get_attributions(id3)
    assert len(attrs3) == 1
    assert attrs3[0].family.id == attrs2[0].family.id  # Inherits same family

    await db.close()
