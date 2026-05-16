from __future__ import annotations

import aiohttp


class HttpClient:
    """Shared aiohttp session for outbound API calls."""

    def __init__(self) -> None:
        self.session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        timeout = aiohttp.ClientTimeout(total=20, connect=5)
        self.session = aiohttp.ClientSession(timeout=timeout)

    def get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            raise RuntimeError("HTTP client has not been started")
        return self.session

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()

