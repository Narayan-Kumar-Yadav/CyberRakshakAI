from __future__ import annotations

import json
import logging
from time import perf_counter

from app.config import Settings
from app.models.threat_report import ThreatReport
from app.observability.json_logging import log_extra
from app.observability.timing import elapsed_ms
from app.services.http_client import HttpClient

logger = logging.getLogger(__name__)


class GeminiProvider:
    """Low-level Google Gemini REST provider.

    Uses the official generateContent REST shape:
    https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
    """

    def __init__(self, settings: Settings, http_client: HttpClient) -> None:
        self.settings = settings
        self.http_client = http_client

    async def generate(self, prompt: str) -> str:
        if not self.settings.gemini_api_key:
            return "Gemini explanation is disabled because GEMINI_API_KEY is not configured."

        start = perf_counter()
        logger.info("Gemini started", **log_extra("gemini.started", model=self.settings.gemini_model))
        session = self.http_client.get_session()
        url = f"{self.settings.gemini_api_base_url.rstrip('/')}/models/{self.settings.gemini_model}:generateContent"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 650},
            "safetySettings": [
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}
            ],
        }
        headers = {"x-goog-api-key": self.settings.gemini_api_key, "Content-Type": "application/json"}

        async with session.post(url, headers=headers, json=payload) as response:
            if response.status >= 400:
                logger.warning(
                    "Gemini request failed",
                    **log_extra(
                        "gemini.failed",
                        model=self.settings.gemini_model,
                        status=response.status,
                        duration_ms=elapsed_ms(start),
                    ),
                )
                return "Gemini explanation is temporarily unavailable."
            data = await response.json()

        try:
            parts = data["candidates"][0]["content"]["parts"]
            content = "\n".join(str(part.get("text", "")).strip() for part in parts if part.get("text")).strip()
            logger.info(
                "Gemini completed",
                **log_extra("gemini.completed", model=self.settings.gemini_model, duration_ms=elapsed_ms(start)),
            )
            return content
        except (KeyError, IndexError, TypeError):
            logger.warning(
                "Unexpected Gemini response shape",
                **log_extra("gemini.failed", model=self.settings.gemini_model, duration_ms=elapsed_ms(start)),
            )
            return "Gemini returned an unexpected response."


class GeminiCybersecurityAssistant:
    """Assistant logic kept separate from provider transport and auth details."""

    SYSTEM_GUIDANCE = (
        "You are CyberRakshak.ai, a defensive cybersecurity analyst. "
        "Explain threat-intelligence reports clearly for everyday users. "
        "Do not provide exploitation, malware, credential theft, evasion, or abuse instructions. "
        "Never ask for passwords, OTPs, seed phrases, private keys, or secret tokens. "
        "Base the verdict on the provided structured report; do not invent provider findings."
    )

    def __init__(self, provider: GeminiProvider) -> None:
        self.provider = provider

    async def explain_report(self, report: ThreatReport) -> str:
        prompt = (
            f"{self.SYSTEM_GUIDANCE}\n\n"
            "Create a concise explanation with these sections: Verdict, Why it was scored this way, "
            "What to do next. Keep it under 180 words.\n\n"
            f"Structured threat report JSON:\n{json.dumps(report.compact_dict(), ensure_ascii=True)}"
        )
        return await self.provider.generate(prompt)

    async def answer(self, question: str) -> str:
        prompt = (
            f"{self.SYSTEM_GUIDANCE}\n\n"
            "Answer this defensive cybersecurity question with practical prevention guidance:\n"
            f"{question}"
        )
        return await self.provider.generate(prompt)
