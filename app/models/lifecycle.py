from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class BackgroundTask:
    id: int
    task_type: str
    payload: dict[str, Any]
    status: str
    next_run_at: str
    retry_count: int
    created_at: str


@dataclass
class EnrichmentJob:
    indicator_type: str
    indicator_value: str
    provider_name: str
    target_ioc_id: int
