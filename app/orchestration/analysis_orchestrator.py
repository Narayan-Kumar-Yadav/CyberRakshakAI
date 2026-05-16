from __future__ import annotations

import logging
from time import perf_counter

from app.config import Settings
from app.models.threat_report import ThreatReport
from app.observability.json_logging import log_extra
from app.observability.metrics import increment_metric_safe
from app.observability.timing import elapsed_ms, latency_bucket
from app.orchestration.enrichment_pipeline import EnrichmentPipeline
from app.orchestration.report_builder import ThreatReportBuilder
from app.scoring.confidence_engine import ConfidenceScoringEngine
from app.scoring.risk_engine import RiskScoringEngine
from app.services.gemini_service import GeminiCybersecurityAssistant
from app.services.intelligence_query_service import IntelligenceQueryService
from app.services.ioc_persistence import IOCPersistenceService
from app.repositories.jobs_repository import JobsRepository
from app.services.redis_cache import RedisClient

logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """Coordinates enrichment, scoring, report building, and optional AI explanation."""

    def __init__(
        self,
        settings: Settings,
        redis: RedisClient,
        enrichment_pipeline: EnrichmentPipeline,
        risk_engine: RiskScoringEngine,
        confidence_engine: ConfidenceScoringEngine,
        report_builder: ThreatReportBuilder,
        gemini: GeminiCybersecurityAssistant,
        ioc_persistence: IOCPersistenceService | None = None,
        intelligence_query_service: IntelligenceQueryService | None = None,
        jobs_repo: JobsRepository | None = None,
    ) -> None:
        self.settings = settings
        self.redis = redis
        self.enrichment_pipeline = enrichment_pipeline
        self.risk_engine = risk_engine
        self.confidence_engine = confidence_engine
        self.report_builder = report_builder
        self.gemini = gemini
        self.ioc_persistence = ioc_persistence
        self.intelligence_query_service = intelligence_query_service
        self.jobs_repo = jobs_repo

    async def analyze(self, text: str, include_ai: bool = True) -> ThreatReport:
        start = perf_counter()
        await increment_metric_safe(self.redis, "analysis_started", ttl_seconds=self.settings.metrics_ttl_seconds)
        logger.info("Threat analysis started", **log_extra("analysis.started", include_ai=include_ai))
        try:
            enrichment = await self.enrichment_pipeline.enrich(text)

            historical_context = None
            if self.intelligence_query_service and enrichment.local_result.indicator.type != "message":
                historical_context = await self.intelligence_query_service.get_ioc_summary(
                    enrichment.local_result.indicator.type, 
                    enrichment.local_result.indicator.value.lower()
                )

            risk_score = self.risk_engine.score(enrichment.local_result.risk_score, enrichment.provider_results, historical_context)
            confidence = self.confidence_engine.score(enrichment.provider_executions, historical_context)
            report = self.report_builder.build(enrichment, risk_score, confidence, historical_context=historical_context)

            if include_ai:
                explanation = await self.gemini.explain_report(report)
                report = self.report_builder.build(enrichment, risk_score, confidence, ai_explanation=explanation, historical_context=historical_context)

            ioc_id = None
            if self.ioc_persistence:
                ioc_id = await self.ioc_persistence.record_threat_report(report)

            if ioc_id and self.jobs_repo:
                for execution in report.provider_executions:
                    if execution.status == "timeout" or (execution.result and execution.result.status == "pending"):
                        logger.info(f"Enqueuing deferred enrichment for {execution.provider_name} on {report.target.value}")
                        await self.jobs_repo.enqueue_job(
                            task_type="deferred_enrichment",
                            payload={
                                "provider_name": execution.provider_name,
                                "target_ioc_id": ioc_id,
                                "indicator_type": report.target.type,
                                "indicator_value": report.target.value.lower(),
                            },
                            delay_seconds=60  # Re-check in 1 minute
                        )

                if report.provider_results:
                    provider_dicts = [
                        {
                            "source": pr.source,
                            "indicator": {"type": pr.indicator.type, "value": pr.indicator.value},
                            "status": pr.status,
                            "risk_score": pr.risk_score,
                            "risk_level": pr.risk_level.value,
                            "malicious": pr.malicious,
                            "suspicious": pr.suspicious,
                            "metadata": pr.metadata,
                        }
                        for pr in report.provider_results
                    ]
                    await self.jobs_repo.enqueue_job(
                        task_type="correlate_relationships",
                        payload={
                            "source_ioc_id": ioc_id,
                            "indicator_type": report.target.type,
                            "provider_results": provider_dicts,
                        },
                        delay_seconds=0
                    )

            duration = elapsed_ms(start)
            await increment_metric_safe(
                self.redis,
                "analysis_latency_bucket",
                {"bucket": latency_bucket(duration), "target_type": report.target.type},
                ttl_seconds=self.settings.metrics_ttl_seconds,
            )
            await increment_metric_safe(
                self.redis,
                "analysis_completed",
                {
                    "risk_level": report.risk_level.value,
                    "confidence_level": report.confidence_level.value,
                    "target_type": report.target.type,
                },
                ttl_seconds=self.settings.metrics_ttl_seconds,
            )
            logger.info(
                "Threat analysis completed",
                **log_extra(
                    "analysis.completed",
                    target_type=report.target.type,
                    risk_level=report.risk_level.value,
                    risk_score=report.risk_score,
                    confidence_level=report.confidence_level.value,
                    confidence_score=report.confidence_score,
                    provider_count=len(report.provider_results),
                    partial_results=report.partial_results,
                    duration_ms=duration,
                ),
            )
            return report
        except Exception:
            duration = elapsed_ms(start)
            await increment_metric_safe(self.redis, "analysis_failed", ttl_seconds=self.settings.metrics_ttl_seconds)
            logger.exception("Threat analysis failed", **log_extra("analysis.failed", duration_ms=duration))
            raise
