from __future__ import annotations

import logging
from datetime import datetime

from app.models.correlation import IOCActivitySummary

logger = logging.getLogger(__name__)


class IOCAgingService:
    """Calculates confidence decay over time for stale intelligence."""

    def __init__(self) -> None:
        self.decay_rate_per_30_days = 5  # Reduce confidence score by 5 points every 30 days of inactivity

    def calculate_decayed_confidence(self, base_confidence: int, historical_context: IOCActivitySummary | None) -> int:
        if not historical_context:
            return base_confidence

        last_seen = historical_context.ioc.last_seen_at
        try:
            # Assumes format "YYYY-MM-DD HH:MM:SS" from SQLite CURRENT_TIMESTAMP
            last_seen_dt = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return base_confidence

        days_stale = (datetime.utcnow() - last_seen_dt).days
        if days_stale < 30:
            return base_confidence

        decay_intervals = days_stale // 30
        decay = decay_intervals * self.decay_rate_per_30_days

        new_confidence = max(0, base_confidence - decay)
        return new_confidence

    def get_decay_factor_description(self, days_stale: int) -> str:
        if days_stale >= 30:
            return f"confidence decayed due to {days_stale} days of inactivity"
        return ""
