import hashlib
import json
import logging

from app.models.api_results import NormalizedThreatResult
from app.models.attribution import ThreatFingerprint
from app.observability.metrics import increment_metric_safe
from app.repositories.fingerprint_repository import FingerprintRepository
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class FingerprintingService:
    """Generates deterministic behavioral fingerprints and calculates similarity."""

    def __init__(self, fp_repo: FingerprintRepository, redis: RedisClient | None = None) -> None:
        self.fp_repo = fp_repo
        self.redis = redis

    async def generate_and_persist(
        self, ioc_id: int, provider_results: list[NormalizedThreatResult]
    ) -> ThreatFingerprint:
        """Deterministically hashes behavioral indicators to generate a fingerprint."""
        redirects = []
        asns = []
        metadata = {}
        for res in provider_results:
            if not res.metadata:
                continue
            if "redirects_to" in res.metadata:
                redirects.extend(res.metadata["redirects_to"])
            if "asn" in res.metadata:
                asns.append(str(res.metadata["asn"]))
            metadata[res.source] = res.metadata

        redirect_hash = None
        if redirects:
            redirects.sort()
            redirect_hash = hashlib.sha256(",".join(redirects).encode()).hexdigest()

        asn = asns[0] if asns else None

        meta_hash = None
        if metadata:
            meta_hash = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()

        fp = ThreatFingerprint(
            ioc_id=ioc_id, redirect_chain_hash=redirect_hash, hosting_asn=asn, metadata_hash=meta_hash
        )
        await self.fp_repo.upsert_fingerprint(fp)

        if self.redis:
            await increment_metric_safe(self.redis, "fingerprint_generated", {})

        return fp

    async def calculate_similarity_and_attribute(self, fp: ThreatFingerprint, base_risk_score: int) -> None:
        """Finds overlap with past fingerprints and attributes to known families if applicable."""
        # Only spend resources attributing infrastructure that is actually risky
        if base_risk_score < 60:
            return

        similar_ioc_ids = await self.fp_repo.find_similar_iocs(fp, fp.ioc_id)
        if not similar_ioc_ids:
            return

        # We found similar malicious infrastructure!
        if self.redis:
            await increment_metric_safe(self.redis, "similarity_match_found", {"count": str(len(similar_ioc_ids))})

        attributed = False
        for similar_id in similar_ioc_ids:
            attributions = await self.fp_repo.get_attributions(similar_id)
            for attr in attributions:
                # Inherit the attribution
                await self.fp_repo.record_attribution(fp.ioc_id, attr.family.id, confidence=75, similarity_score=0.8)
                attributed = True
                if self.redis:
                    await increment_metric_safe(self.redis, "threat_family_attributed", {"family": attr.family.name})

        # Auto-create a family if we detect recurring infrastructure reuse but no existing family
        if not attributed and len(similar_ioc_ids) >= 1:
            fam_name = f"Campaign-ASN-{fp.hosting_asn}" if fp.hosting_asn else f"Campaign-Hash-{fp.redirect_chain_hash[:8]}"
            family = await self.fp_repo.get_or_create_threat_family(
                fam_name, description="Auto-generated campaign cluster from shared infrastructure fingerprints."
            )
            # Attribute current IOC
            await self.fp_repo.record_attribution(fp.ioc_id, family.id, confidence=80, similarity_score=1.0)
            # Attribute the historical IOCs
            for similar_id in similar_ioc_ids:
                await self.fp_repo.record_attribution(similar_id, family.id, confidence=80, similarity_score=1.0)

            logger.info(f"Auto-generated new Threat Family: {fam_name} connecting {len(similar_ioc_ids) + 1} nodes.")
