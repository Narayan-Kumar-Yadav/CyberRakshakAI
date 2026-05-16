from __future__ import annotations

import logging

from app.models.attribution import AttributionHint, ThreatFamily, ThreatFingerprint
from app.repositories.database import Database

logger = logging.getLogger(__name__)


class FingerprintRepository:
    """Manages the persistence of threat fingerprints and attributions."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def upsert_fingerprint(self, fingerprint: ThreatFingerprint) -> None:
        query = """
            INSERT INTO ioc_fingerprints (ioc_id, redirect_chain_hash, hosting_asn, metadata_hash)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ioc_id) DO UPDATE SET
                redirect_chain_hash = excluded.redirect_chain_hash,
                hosting_asn = excluded.hosting_asn,
                metadata_hash = excluded.metadata_hash
        """
        await self.db.conn().execute(
            query,
            (fingerprint.ioc_id, fingerprint.redirect_chain_hash, fingerprint.hosting_asn, fingerprint.metadata_hash),
        )
        await self.db.conn().commit()

    async def get_fingerprint(self, ioc_id: int) -> ThreatFingerprint | None:
        query = "SELECT * FROM ioc_fingerprints WHERE ioc_id = ?"
        async with self.db.conn().execute(query, (ioc_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return ThreatFingerprint(
                    ioc_id=row["ioc_id"],
                    redirect_chain_hash=row["redirect_chain_hash"],
                    hosting_asn=row["hosting_asn"],
                    metadata_hash=row["metadata_hash"],
                )
        return None

    async def get_or_create_threat_family(self, name: str, description: str = "") -> ThreatFamily:
        query = "SELECT id, name, description FROM threat_families WHERE name = ?"
        async with self.db.conn().execute(query, (name,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return ThreatFamily(id=row["id"], name=row["name"], description=row["description"])

        # Create
        query = "INSERT INTO threat_families (name, description) VALUES (?, ?) RETURNING id"
        async with self.db.conn().execute(query, (name, description)) as cursor:
            row = await cursor.fetchone()
            if row:
                fam = ThreatFamily(id=row["id"], name=name, description=description)
                await self.db.conn().commit()
                return fam
        raise RuntimeError("Failed to create threat family")

    async def get_threat_family(self, family_id: int) -> ThreatFamily | None:
        query = "SELECT * FROM threat_families WHERE id = ?"
        async with self.db.conn().execute(query, (family_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return ThreatFamily(id=row["id"], name=row["name"], description=row["description"])
        return None

    async def record_attribution(self, ioc_id: int, family_id: int, confidence: int, similarity_score: float) -> None:
        query = """
            INSERT INTO ioc_attributions (ioc_id, family_id, confidence, similarity_score)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ioc_id, family_id) DO UPDATE SET
                confidence = MAX(confidence, excluded.confidence),
                similarity_score = MAX(similarity_score, excluded.similarity_score)
        """
        await self.db.conn().execute(query, (ioc_id, family_id, confidence, similarity_score))
        await self.db.conn().commit()

    async def get_attributions(self, ioc_id: int) -> list[AttributionHint]:
        query = """
            SELECT a.confidence, a.similarity_score, f.id, f.name, f.description
            FROM ioc_attributions a
            JOIN threat_families f ON a.family_id = f.id
            WHERE a.ioc_id = ?
            ORDER BY a.confidence DESC, a.similarity_score DESC
        """
        results = []
        async with self.db.conn().execute(query, (ioc_id,)) as cursor:
            async for row in cursor:
                results.append(
                    AttributionHint(
                        family=ThreatFamily(id=row["id"], name=row["name"], description=row["description"]),
                        confidence=row["confidence"],
                        similarity_score=row["similarity_score"],
                    )
                )
        return results

    async def find_similar_iocs(self, fingerprint: ThreatFingerprint, exclude_ioc_id: int) -> list[int]:
        """Finds IOCs that share exact hashes with the given fingerprint."""
        conditions = []
        params: list[int | str] = []
        if fingerprint.redirect_chain_hash:
            conditions.append("redirect_chain_hash = ?")
            params.append(fingerprint.redirect_chain_hash)
        if fingerprint.hosting_asn:
            conditions.append("hosting_asn = ?")
            params.append(fingerprint.hosting_asn)
        if fingerprint.metadata_hash:
            conditions.append("metadata_hash = ?")
            params.append(fingerprint.metadata_hash)

        if not conditions:
            return []

        query = f"SELECT ioc_id FROM ioc_fingerprints WHERE ioc_id != ? AND ({' OR '.join(conditions)})"
        params.insert(0, exclude_ioc_id)

        results = []
        async with self.db.conn().execute(query, tuple(params)) as cursor:
            async for row in cursor:
                results.append(row["ioc_id"])
        return results
