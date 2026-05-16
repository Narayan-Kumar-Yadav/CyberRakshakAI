from __future__ import annotations

import logging

from app.models.graph import CampaignCluster, RelatedIOC, RelationshipType
from app.repositories.database import Database

logger = logging.getLogger(__name__)


class RelationshipRepository:
    """Manages the persistent intelligence graph mappings in SQLite."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def upsert_relationship(
        self, source_ioc_id: int, target_ioc_id: int, relationship_type: RelationshipType, confidence: int = 50
    ) -> None:
        if source_ioc_id == target_ioc_id:
            return  # Prevent self-loops

        query = """
            INSERT INTO ioc_relationships (source_ioc_id, target_ioc_id, relationship_type, confidence)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source_ioc_id, target_ioc_id, relationship_type)
            DO UPDATE SET
                last_seen_at = CURRENT_TIMESTAMP,
                confidence = MAX(confidence, excluded.confidence)
        """
        await self.db.conn().execute(query, (source_ioc_id, target_ioc_id, relationship_type.value, confidence))
        await self.db.conn().commit()

    async def get_related_iocs(self, ioc_id: int) -> list[RelatedIOC]:
        """Fetch all directly connected IOCs (1st degree neighborhood)."""
        query = """
            SELECT r.target_ioc_id as id, i.indicator_type, i.indicator_value, r.relationship_type, r.confidence, i.cumulative_risk_score
            FROM ioc_relationships r
            JOIN iocs i ON r.target_ioc_id = i.id
            WHERE r.source_ioc_id = ?
            UNION
            SELECT r.source_ioc_id as id, i.indicator_type, i.indicator_value, r.relationship_type, r.confidence, i.cumulative_risk_score
            FROM ioc_relationships r
            JOIN iocs i ON r.source_ioc_id = i.id
            WHERE r.target_ioc_id = ?
        """
        results = []
        async with self.db.conn().execute(query, (ioc_id, ioc_id)) as cursor:
            async for row in cursor:
                results.append(
                    RelatedIOC(
                        id=row["id"],
                        indicator_type=row["indicator_type"],
                        indicator_value=row["indicator_value"],
                        relationship_type=RelationshipType(row["relationship_type"]),
                        relationship_confidence=row["confidence"],
                        cumulative_risk_score=row["cumulative_risk_score"],
                    )
                )
        return results

    async def get_campaign_cluster(self, start_ioc_id: int, max_depth: int = 3) -> CampaignCluster:
        """Execute a recursive CTE to find all connected nodes in the campaign infrastructure."""
        query = f"""
            WITH RECURSIVE cluster AS (
                SELECT source_ioc_id as from_id, target_ioc_id as to_id, relationship_type, confidence, 1 as depth
                FROM ioc_relationships
                WHERE source_ioc_id = ? OR target_ioc_id = ?
                
                UNION
                
                SELECT r.source_ioc_id, r.target_ioc_id, r.relationship_type, r.confidence, c.depth + 1
                FROM ioc_relationships r
                JOIN cluster c ON r.source_ioc_id = c.to_id OR r.target_ioc_id = c.to_id OR r.source_ioc_id = c.from_id OR r.target_ioc_id = c.from_id
                WHERE c.depth < {max_depth}
            )
            SELECT DISTINCT i.id, i.indicator_type, i.indicator_value, i.cumulative_risk_score
            FROM cluster c
            JOIN iocs i ON c.from_id = i.id OR c.to_id = i.id
            WHERE i.id != ?
        """
        nodes = []
        total_risk = 0
        max_risk = 0

        async with self.db.conn().execute(query, (start_ioc_id, start_ioc_id, start_ioc_id)) as cursor:
            async for row in cursor:
                risk = row["cumulative_risk_score"]
                total_risk += risk
                if risk > max_risk:
                    max_risk = risk

                nodes.append(
                    RelatedIOC(
                        id=row["id"],
                        indicator_type=row["indicator_type"],
                        indicator_value=row["indicator_value"],
                        relationship_type=RelationshipType.PART_OF_CAMPAIGN,  # Abstract type for cluster view
                        relationship_confidence=50,
                        cumulative_risk_score=risk,
                    )
                )

        avg_risk = total_risk // len(nodes) if nodes else 0
        return CampaignCluster(root_ioc_id=start_ioc_id, nodes=nodes, average_risk=avg_risk, max_risk=max_risk)
