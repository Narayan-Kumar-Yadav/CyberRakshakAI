import logging

from app.models.jobs import BackgroundTask
from app.streaming.event_processor import EventProcessor
from app.streaming.feed_manager import FeedManager

logger = logging.getLogger(__name__)


class FeedSyncJobHandler:
    """Background task handler that periodically polls active feed sources."""

    def __init__(self, feed_manager: FeedManager, event_processor: EventProcessor) -> None:
        self.feed_manager = feed_manager
        self.event_processor = event_processor

    async def handle(self, task: BackgroundTask) -> None:
        logger.info("Executing background feed sync...")
        count = 0
        async for event in self.feed_manager.poll_all():
            update = await self.event_processor.process_event(event)
            if update:
                count += 1
        logger.info(f"Feed sync complete. Processed {count} new live events.")
