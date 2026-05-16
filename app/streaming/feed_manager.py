from abc import ABC, abstractmethod
from typing import AsyncGenerator

from app.models.streaming import LiveThreatEvent


class FeedSource(ABC):
    """Interface for live threat intelligence feed sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def poll_recent(self) -> AsyncGenerator[LiveThreatEvent, None]:
        pass


class FeedManager:
    """Manages registered feed sources and orchestrates polling."""

    def __init__(self) -> None:
        self.sources: list[FeedSource] = []

    def register(self, source: FeedSource) -> None:
        self.sources.append(source)

    async def poll_all(self) -> AsyncGenerator[LiveThreatEvent, None]:
        """Polls all registered sources for recent events."""
        for source in self.sources:
            async for event in source.poll_recent():
                yield event
