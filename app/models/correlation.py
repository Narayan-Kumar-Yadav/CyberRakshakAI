from __future__ import annotations

from dataclasses import dataclass, field

from app.models.attribution import AttributionHint
from app.models.ioc import IOCRecord, ThreatObservation
from app.models.graph import CampaignCluster


@dataclass
class IOCTrend:
    direction: str  # "increasing", "decreasing", "stable", "volatile", "insufficient_data"
    velocity: float


@dataclass
class IOCProviderCorrelation:
    agreement_score: float
    most_frequent_confidence_level: str


@dataclass
class HistoricalRiskSnapshot:
    average_risk: int
    peak_risk: int
    first_seen: str
    last_seen: str


@dataclass
class IOCActivitySummary:
    ioc: IOCRecord
    recent_observations: list[ThreatObservation]
    trend: IOCTrend
    provider_correlation: IOCProviderCorrelation
    risk_snapshot: HistoricalRiskSnapshot
    campaign_cluster: CampaignCluster | None = None
    attributions: list[AttributionHint] = field(default_factory=list)
