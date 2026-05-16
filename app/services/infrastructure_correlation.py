from __future__ import annotations

import logging

from app.models.api_results import NormalizedThreatResult
from app.models.graph import RelationshipType
from app.observability.metrics import increment_metric_safe
from app.repositories.ioc_repository import IOCRepository
from app.repositories.relationship_repository import RelationshipRepository
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class InfrastructureCorrelationService:
    """Builds the threat graph by extracting relationships from enrichment metadata."""

    def __init__(
        self, ioc_repo: IOCRepository, rel_repo: RelationshipRepository, redis: RedisClient | None = None
    ) -> None:
        self.ioc_repo = ioc_repo
        self.rel_repo = rel_repo
        self.redis = redis

    async def correlate_from_enrichment(
        self, source_ioc_id: int, indicator_type: str, provider_results: list[NormalizedThreatResult]
    ) -> None:
        """Extract relationships from metadata and persist them as graph edges."""
        edges_created = 0

        for result in provider_results:
            if not result.metadata:
                continue

            # Extract IP resolutions from Domains or URLs
            if "resolved_ips" in result.metadata and indicator_type in ("domain", "url"):
                for ip in result.metadata["resolved_ips"]:
                    target_id = await self.ioc_repo.upsert_ioc("ip", ip, risk_score=0)
                    await self.rel_repo.upsert_relationship(source_ioc_id, target_id, RelationshipType.RESOLVES_TO)
                    edges_created += 1
                    if self.redis:
                        await increment_metric_safe(
                            self.redis, "relationship_created", {"type": RelationshipType.RESOLVES_TO.value}
                        )

            # Extract HTTP redirects
            if "redirects_to" in result.metadata:
                for redirect in result.metadata["redirects_to"]:
                    target_id = await self.ioc_repo.upsert_ioc("url", redirect, risk_score=0)
                    await self.rel_repo.upsert_relationship(source_ioc_id, target_id, RelationshipType.REDIRECTS_TO)
                    edges_created += 1
                    if self.redis:
                        await increment_metric_safe(
                            self.redis, "relationship_created", {"type": RelationshipType.REDIRECTS_TO.value}
                        )

        if edges_created > 0:
            logger.info(f"Correlated {edges_created} new infrastructure relationships for IOC {source_ioc_id}")

            # Check if this node is now part of a malicious campaign cluster
            cluster = await self.rel_repo.get_campaign_cluster(source_ioc_id)
            if len(cluster.nodes) >= 3 and cluster.max_risk >= 65:
                if self.redis:
                    await increment_metric_safe(
                        self.redis, "campaign_cluster_detected", {"root_id": str(source_ioc_id)}
                    )
