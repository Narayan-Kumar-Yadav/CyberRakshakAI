from __future__ import annotations

from dataclasses import dataclass

@dataclass
class IOCRecord:
    id: int
    indicator_type: str
    indicator_value: str
    first_seen_at: str
    last_seen_at: str
    total_observations: int
    cumulative_risk_score: int

@dataclass
class ThreatObservation:
    id: int
    ioc_id: int
    provider_hits: int
    risk_score: int
    confidence_score: int
    confidence_level: str
    created_at: str
