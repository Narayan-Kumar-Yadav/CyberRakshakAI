from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class UsernameAnalysis:
    username: str
    risk_level: str
    score: int
    signals: list[str]
    recommendations: list[str]


class UsernameAnalyzer:
    """Static risk analysis for Telegram usernames without scraping Telegram."""

    RESERVED_WORDS = {"admin", "support", "security", "verify", "helpdesk", "official", "telegram"}
    RISKY_PATTERNS = [
        re.compile(r"[_\-.]{2,}"),
        re.compile(r"\d{4,}$"),
        re.compile(r"(?i)(free|gift|airdrop|bonus|crypto|wallet|verify|login)"),
    ]

    def analyze(self, username: str) -> UsernameAnalysis:
        cleaned = username.strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", cleaned):
            raise ValueError("Telegram usernames must be 5-32 characters using letters, numbers, or underscores.")

        lowered = cleaned.lower()
        score = 0
        signals: list[str] = []

        if any(word in lowered for word in self.RESERVED_WORDS):
            score += 30
            signals.append("Uses trust-sensitive words such as support, admin, official, or verify.")

        for pattern in self.RISKY_PATTERNS:
            if pattern.search(cleaned):
                score += 20
                signals.append("Contains patterns often seen in impersonation, giveaway, or phishing accounts.")

        if len(cleaned) <= 6:
            score += 10
            signals.append("Very short username; verify identity carefully before trusting it.")

        if not signals:
            signals.append("No obvious static impersonation signals found.")

        risk_level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
        recommendations = [
            "Confirm identity through an independent trusted channel.",
            "Do not share OTPs, passwords, seed phrases, or private keys.",
            "Check profile history, mutual groups, and recent username changes where visible.",
        ]
        return UsernameAnalysis(f"@{cleaned}", risk_level, min(score, 100), signals, recommendations)

