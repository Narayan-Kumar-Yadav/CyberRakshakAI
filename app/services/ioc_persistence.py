from __future__ import annotations

import logging

from app.models.threat_report import ThreatReport
from app.repositories.ioc_repository import IOCRepository

logger = logging.getLogger(__name__)


class IOCPersistenceService:
    """Orchestrates persistence of threat intelligence results."""

    def __init__(self, ioc_repository: IOCRepository) -> None:
        self.ioc_repository = ioc_repository

    async def record_threat_report(self, report: ThreatReport) -> int | None:
        """Persist the findings from a generated threat report. Returns IOC ID if applicable."""
        try:
            if report.target.type == "message":
                return None  # Skip generic messages, focus on exact URLs/Domains/IPs
            
            provider_hits = sum(
                (item.result.malicious + item.result.suspicious)
                for item in report.provider_executions
                if item.result is not None
            )

            # Insert/update the IOC metadata
            ioc_id = await self.ioc_repository.upsert_ioc(
                indicator_type=report.target.type,
                indicator_value=report.target.value.lower(),
                risk_score=report.risk_score,
            )

            # Record this specific occurrence
            await self.ioc_repository.record_observation(
                ioc_id=ioc_id,
                provider_hits=provider_hits,
                risk_score=report.risk_score,
                confidence_score=report.confidence_score,
                confidence_level=report.confidence_level.value,
            )
            
            logger.info(f"Persisted IOC observation for {report.target.type} ({ioc_id})")
            return ioc_id

        except Exception:
            # We log but do not raise, to avoid breaking the user flow
            logger.exception("Failed to persist IOC observation")
            return None
