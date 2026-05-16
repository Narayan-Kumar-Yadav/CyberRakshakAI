from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.config import Settings
from app.repositories.analytics import AnalyticsRepository
from app.repositories.database import Database
from app.repositories.history import HistoryRepository
from app.repositories.users import UserRepository
from app.services.gemini_service import GeminiCybersecurityAssistant, GeminiProvider
from app.services.http_client import HttpClient
from app.services.phishing import PhishingDetector
from app.services.redis_cache import RedisClient
from app.services.threat_intelligence import ThreatIntelligenceService
from app.utils.security import fingerprint_text, html_escape

router = Router(name="assistant")


@router.message(Command("scan"))
async def scan_message(
    message: Message,
    settings: Settings,
    database: Database,
    sanitized_text: str,
) -> None:
    if not message.from_user:
        return
    await UserRepository(database, settings.admin_ids).upsert_from_telegram(message.from_user)

    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /scan paste suspicious text or URL")
        return

    assessment = PhishingDetector().assess(parts[1])
    lines = [
        "<b>Scam / Phishing Assessment</b>",
        f"Threat level: {html_escape(assessment.threat_level)} ({assessment.score}/100)",
        "",
        "<b>Indicators</b>",
        *[f"- {html_escape(item)}" for item in assessment.indicators],
        "",
        "<b>Prevention</b>",
        *[f"- {html_escape(item)}" for item in assessment.recommendations],
    ]

    await HistoryRepository(database).add(
        message.from_user.id,
        "/scan",
        f"Threat={assessment.threat_level}; score={assessment.score}",
        input_hash=fingerprint_text(parts[1]),
        threat_level=assessment.threat_level,
    )
    await AnalyticsRepository(database).track("scan", message.from_user.id, {"risk": assessment.threat_level})
    await message.answer("\n".join(lines))


@router.message(Command("ask"))
async def ask_assistant(
    message: Message,
    settings: Settings,
    database: Database,
    http_client: HttpClient,
    sanitized_text: str,
) -> None:
    if not message.from_user:
        return
    await UserRepository(database, settings.admin_ids).upsert_from_telegram(message.from_user)

    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /ask How do I secure my Telegram account?")
        return

    answer = await GeminiCybersecurityAssistant(GeminiProvider(settings, http_client)).answer(parts[1])
    await HistoryRepository(database).add(
        message.from_user.id,
        "/ask",
        "Gemini cybersecurity guidance requested",
        input_hash=fingerprint_text(parts[1]),
    )
    await AnalyticsRepository(database).track("ask", message.from_user.id)
    await message.answer(html_escape(answer))


@router.message(Command("analyze"))
async def analyze_threat(
    message: Message,
    settings: Settings,
    database: Database,
    redis: RedisClient,
    http_client: HttpClient,
    sanitized_text: str,
) -> None:
    if not message.from_user:
        return
    await UserRepository(database, settings.admin_ids).upsert_from_telegram(message.from_user)

    parts = sanitized_text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /analyze URL, IP, domain, or suspicious message")
        return

    report = await ThreatIntelligenceService(settings, database, http_client, redis).analyze(parts[1])
    provider_lines = []
    for result in report.provider_results[:5]:
        provider_lines.append(
            f"- {html_escape(result.source)} {html_escape(result.indicator.type)}: "
            f"{html_escape(result.risk_level.value)} ({result.risk_score}/100), "
            f"malicious={result.malicious}, suspicious={result.suspicious}, status={html_escape(result.status)}"
        )
    if not provider_lines:
        provider_lines.append("- No external IOC provider lookup was applicable.")

    lines = [
        "<b>Threat Intelligence Report</b>",
        f"Target: {html_escape(report.target.type)}",
        f"Risk: {html_escape(report.risk_level.value)} ({report.risk_score}/100)",
        f"Confidence: {html_escape(report.confidence_level.value)} ({report.confidence_score}/100)",
        f"Summary: {html_escape(report.summary)}",
        f"Provider coverage: {html_escape(str(report.provider_summary.get('completed', 0)))} completed"
        f" / {html_escape(str(report.provider_summary.get('requested', 0)))} requested",
        "",
        "<b>Signals</b>",
        *[f"- {html_escape(item)}" for item in report.local_result.signals[:6]],
        "",
        "<b>Provider Results</b>",
        *provider_lines,
        "",
        "<b>Recommendations</b>",
        *[f"- {html_escape(item)}" for item in report.recommendations[:6]],
        "",
        "<b>Confidence</b>",
        html_escape(report.confidence_explanation),
    ]
    if report.ai_explanation:
        lines.extend(["", "<b>Gemini Explanation</b>", html_escape(report.ai_explanation)])

    await HistoryRepository(database).add(
        message.from_user.id,
        "/analyze",
        f"{report.target.type} risk={report.risk_level.value}; score={report.risk_score}",
        input_hash=fingerprint_text(parts[1]),
        threat_level=report.risk_level.value,
    )
    await AnalyticsRepository(database).track(
        "threat_analyze",
        message.from_user.id,
        {"risk": report.risk_level.value, "target_type": report.target.type},
    )
    await message.answer("\n".join(lines))
