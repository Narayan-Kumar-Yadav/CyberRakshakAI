from __future__ import annotations

from app.config import Settings
from app.orchestration.analysis_orchestrator import AnalysisOrchestrator
from app.orchestration.enrichment_pipeline import EnrichmentPipeline
from app.orchestration.report_builder import ThreatReportBuilder
from app.providers.adapters import AbuseIPDBProvider, URLScanProvider, URLhausProvider, VirusTotalProvider
from app.providers.registry import ProviderRegistry
from app.scoring.confidence_engine import ConfidenceScoringEngine
from app.scoring.risk_engine import RiskScoringEngine
from app.services.abuseipdb import AbuseIPDBService
from app.services.gemini_service import GeminiCybersecurityAssistant, GeminiProvider
from app.services.http_client import HttpClient
from app.services.phishing import PhishingDetector
from app.services.redis_cache import RedisClient
from app.services.urlhaus import URLhausService
from app.services.urlscan import URLScanService
from app.services.virustotal import VirusTotalService
from app.repositories.database import Database
from app.repositories.fingerprint_repository import FingerprintRepository
from app.repositories.ioc_repository import IOCRepository
from app.repositories.jobs_repository import JobsRepository
from app.repositories.relationship_repository import RelationshipRepository
from app.services.intelligence_query_service import IntelligenceQueryService
from app.services.ioc_persistence import IOCPersistenceService


class ThreatIntelligenceService:
    """Compatibility facade for threat analysis orchestration."""

    def __init__(self, settings: Settings, database: Database, http_client: HttpClient, redis: RedisClient) -> None:
        provider_registry = ProviderRegistry(redis, metrics_ttl_seconds=settings.metrics_ttl_seconds)
        enabled = settings.enabled_providers
        provider_registry.register(
            VirusTotalProvider(
                service=VirusTotalService(settings, http_client, redis),
                timeout_seconds=settings.provider_timeout_seconds,
                enabled="virustotal" in enabled,
            )
        )
        provider_registry.register(
            URLhausProvider(
                service=URLhausService(http_client, redis),
                timeout_seconds=settings.provider_timeout_seconds,
                enabled="urlhaus" in enabled,
            )
        )
        provider_registry.register(
            AbuseIPDBProvider(
                service=AbuseIPDBService(settings, http_client, redis),
                timeout_seconds=settings.provider_timeout_seconds,
                enabled="abuseipdb" in enabled,
            )
        )
        provider_registry.register(
            URLScanProvider(
                service=URLScanService(settings, http_client, redis),
                timeout_seconds=settings.provider_timeout_seconds,
                enabled="urlscan" in enabled,
            )
        )

        self.orchestrator = AnalysisOrchestrator(
            settings=settings,
            redis=redis,
            enrichment_pipeline=EnrichmentPipeline(PhishingDetector(), provider_registry),
            risk_engine=RiskScoringEngine(),
            confidence_engine=ConfidenceScoringEngine(),
            report_builder=ThreatReportBuilder(),
            gemini=GeminiCybersecurityAssistant(GeminiProvider(settings, http_client)),
            ioc_persistence=IOCPersistenceService(IOCRepository(database)),
            intelligence_query_service=IntelligenceQueryService(IOCRepository(database), redis, RelationshipRepository(database), FingerprintRepository(database)),
            jobs_repo=JobsRepository(database),
        )

    async def analyze(self, text: str, include_ai: bool = True):
        return await self.orchestrator.analyze(text, include_ai=include_ai)
