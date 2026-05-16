from __future__ import annotations

import logging
from typing import Optional

from app.models.ioc import IOCRecord, ThreatObservation
from app.repositories.database import Database

logger = logging.getLogger(__name__)


class IOCRepository:
    """Repository for managing indicators of compromise persistence."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def upsert_ioc(self, indicator_type: str, indicator_value: str, risk_score: int) -> int:
        """Upsert an IOC, returning its ID."""
        query = """
            INSERT INTO iocs (indicator_type, indicator_value, total_observations, cumulative_risk_score)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(indicator_type, indicator_value)
            DO UPDATE SET
                last_seen_at = CURRENT_TIMESTAMP,
                total_observations = total_observations + 1,
                cumulative_risk_score = MAX(cumulative_risk_score, excluded.cumulative_risk_score)
            RETURNING id;
        """
        async with self.db.conn().execute(query, (indicator_type, indicator_value, risk_score)) as cursor:
            row = await cursor.fetchone()
            if not row:
                raise RuntimeError("Failed to upsert IOC")
            await self.db.conn().commit()
            return row["id"]

    async def record_observation(
        self, ioc_id: int, provider_hits: int, risk_score: int, confidence_score: int, confidence_level: str
    ) -> None:
        """Record a specific observation point in time for an IOC."""
        query = """
            INSERT INTO threat_observations (ioc_id, provider_hits, risk_score, confidence_score, confidence_level)
            VALUES (?, ?, ?, ?, ?)
        """
        await self.db.conn().execute(query, (ioc_id, provider_hits, risk_score, confidence_score, confidence_level))
        await self.db.conn().commit()

    async def get_ioc(self, indicator_type: str, indicator_value: str) -> Optional[IOCRecord]:
        """Fetch an existing IOC."""
        query = "SELECT * FROM iocs WHERE indicator_type = ? AND indicator_value = ?"
        async with self.db.conn().execute(query, (indicator_type, indicator_value)) as cursor:
            row = await cursor.fetchone()
            if row:
                return IOCRecord(
                    id=row["id"],
                    indicator_type=row["indicator_type"],
                    indicator_value=row["indicator_value"],
                    first_seen_at=row["first_seen_at"],
                    last_seen_at=row["last_seen_at"],
                    total_observations=row["total_observations"],
                    cumulative_risk_score=row["cumulative_risk_score"],
                )
            return None

    async def get_ioc_history(self, ioc_id: int, limit: int = 50) -> list[ThreatObservation]:
        """Fetch the observation timeline for an IOC."""
        query = "SELECT * FROM threat_observations WHERE ioc_id = ? ORDER BY created_at DESC LIMIT ?"
        observations = []
        async with self.db.conn().execute(query, (ioc_id, limit)) as cursor:
            async for row in cursor:
                observations.append(
                    ThreatObservation(
                        id=row["id"],
                        ioc_id=row["ioc_id"],
                        provider_hits=row["provider_hits"],
                        risk_score=row["risk_score"],
                        confidence_score=row["confidence_score"],
                        confidence_level=row["confidence_level"],
                        created_at=row["created_at"],
                    )
                )
        return observations

    async def get_recent_iocs(self, limit: int = 10) -> list[IOCRecord]:
        """Fetch recently observed IOCs."""
        query = "SELECT * FROM iocs ORDER BY last_seen_at DESC LIMIT ?"
        return await self._fetch_iocs(query, (limit,))

    async def get_high_risk_iocs(self, limit: int = 10) -> list[IOCRecord]:
        """Fetch the most dangerous recurring IOCs."""
        query = "SELECT * FROM iocs WHERE cumulative_risk_score >= 65 ORDER BY cumulative_risk_score DESC, total_observations DESC LIMIT ?"
        return await self._fetch_iocs(query, (limit,))

    async def get_repeated_iocs(self, min_observations: int = 2, limit: int = 10) -> list[IOCRecord]:
        """Fetch IOCs seen multiple times."""
        query = "SELECT * FROM iocs WHERE total_observations >= ? ORDER BY total_observations DESC LIMIT ?"
        return await self._fetch_iocs(query, (min_observations, limit))

    async def _fetch_iocs(self, query: str, params: tuple) -> list[IOCRecord]:
        results = []
        async with self.db.conn().execute(query, params) as cursor:
            async for row in cursor:
                results.append(
                    IOCRecord(
                        id=row["id"],
                        indicator_type=row["indicator_type"],
                        indicator_value=row["indicator_value"],
                        first_seen_at=row["first_seen_at"],
                        last_seen_at=row["last_seen_at"],
                        total_observations=row["total_observations"],
                        cumulative_risk_score=row["cumulative_risk_score"],
                    )
                )
        return results
