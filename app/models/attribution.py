from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ThreatFingerprint:
    ioc_id: int
    redirect_chain_hash: str | None = None
    hosting_asn: str | None = None
    metadata_hash: str | None = None


@dataclass
class ThreatFamily:
    id: int
    name: str
    description: str


@dataclass
class SimilarityScore:
    jaccard_index: float
    exact_matches: int
    matched_features: list[str] = field(default_factory=list)


@dataclass
class AttributionHint:
    family: ThreatFamily
    confidence: int
    similarity_score: float
