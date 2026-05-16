import logging
from typing import Any

from app.config import Settings
from app.models.streaming import IntelligenceUpdate, ThreatEvolutionEvent

logger = logging.getLogger(__name__)


class AlertingService:
    """Dispatches proactive alerts to administrators via Telegram."""

    def __init__(self, bot: Any | None, settings: Settings) -> None:
        self.bot = bot  # aiogram Bot instance
        self.settings = settings

    async def alert_evolution(self, event: ThreatEvolutionEvent) -> None:
        message = (
            f"🚨 <b>Threat Evolution Alert</b>\n"
            f"Type: {event.event_type}\n"
            f"IOC: {event.indicator_value}\n"
            f"Details: {event.description}"
        )
        await self._broadcast(message)

    async def alert_critical_update(self, update: IntelligenceUpdate) -> None:
        if update.event.risk_score >= 80 and update.risk_escalated:
            message = (
                f"🔴 <b>Critical Risk Escalation</b>\n"
                f"IOC: {update.event.indicator_value}\n"
                f"Risk: {update.previous_risk} ➡️ {update.event.risk_score}\n"
                f"Source: {update.event.source_feed}"
            )
            await self._broadcast(message)

    async def _broadcast(self, message: str) -> None:
        if not self.bot:
            logger.warning("Bot instance not provided to AlertingService. Skipping broadcast.")
            return
        for admin_id in self.settings.admin_ids:
            try:
                await self.bot.send_message(chat_id=admin_id, text=message)
            except Exception as e:
                logger.error(f"Failed to send alert to {admin_id}: {e}")
