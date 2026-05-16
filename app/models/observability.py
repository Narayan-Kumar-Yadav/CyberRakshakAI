from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class MetricTags:
    values: dict[str, str] = field(default_factory=dict)

    def safe_dict(self) -> dict[str, str]:
        return {str(key): str(value) for key, value in sorted(self.values.items())}


@dataclass(frozen=True)
class TelemetryEvent:
    event: str
    correlation_id: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class LatencyMetric:
    name: str
    duration_ms: int
    tags: MetricTags = field(default_factory=MetricTags)
    correlation_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

