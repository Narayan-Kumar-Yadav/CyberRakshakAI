from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class LiveThreatEvent:
    event_id: str
    timestamp: datetime
    source_feed: str
    indicator_type: str
    indicator_value: str
    risk_score: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IntelligenceUpdate:
    event: LiveThreatEvent
    is_new_ioc: bool
    risk_escalated: bool
    previous_risk: int


@dataclass
class ThreatEvolutionEvent:
    ioc_id: int
    indicator_value: str
    event_type: str  # e.g., "campaign_expansion", "attribution_escalation", "new_fingerprint"
    description: str
