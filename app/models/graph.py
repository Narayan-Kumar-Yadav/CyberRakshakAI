from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RelationshipType(str, Enum):
    RESOLVES_TO = "resolves_to"
    HOSTED_ON = "hosted_on"
    REDIRECTS_TO = "redirects_to"
    PART_OF_CAMPAIGN = "part_of_campaign"
    SHARES_INFRASTRUCTURE = "shares_infrastructure"


@dataclass
class IOCRelationship:
    source_ioc_id: int
    target_ioc_id: int
    relationship_type: RelationshipType
    confidence: int
    first_seen_at: str
    last_seen_at: str


@dataclass
class RelatedIOC:
    id: int
    indicator_type: str
    indicator_value: str
    relationship_type: RelationshipType
    relationship_confidence: int
    cumulative_risk_score: int


@dataclass
class CampaignCluster:
    root_ioc_id: int
    nodes: list[RelatedIOC] = field(default_factory=list)
    average_risk: int = 0
    max_risk: int = 0


@dataclass
class InfrastructureFingerprint:
    resolved_ips: list[str] = field(default_factory=list)
    redirect_urls: list[str] = field(default_factory=list)
