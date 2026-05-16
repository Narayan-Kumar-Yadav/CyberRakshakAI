from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.models.api_results import Indicator, IndicatorType, LocalHeuristicResult
from app.models.risk_level import risk_from_score


@dataclass(frozen=True)
class ThreatAssessment:
    threat_level: str
    score: int
    indicators: list[str]
    recommendations: list[str]


class PhishingDetector:
    """Rule-based phishing and scam detector used before threat-intel enrichment."""

    URGENCY = re.compile(r"(?i)\b(urgent|immediately|limited time|act now|within 24 hours|final warning)\b")
    CREDENTIALS = re.compile(r"(?i)\b(password|otp|2fa|seed phrase|private key|login|verify account)\b")
    MONEY = re.compile(r"(?i)\b(crypto|wallet|refund|prize|gift card|airdrop|investment|double your money)\b")
    URL = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)
    SHORTENER = re.compile(r"(?i)\b(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|cutt\.ly|shorturl)\b")
    DOMAIN = re.compile(r"(?i)\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b")
    SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "icu", "click", "country", "tk", "gq", "work", "quest"}
    BRAND_IMPERSONATION = re.compile(
        r"(?i)\b(paypa1|micros0ft|g00gle|faceb00k|teIegram|whatsap[p]?[-_]?(support|verify))\b"
    )

    def assess(self, text: str) -> ThreatAssessment:
        result = self.assess_typed(text)
        return ThreatAssessment(
            threat_level=result.risk_level.value,
            score=result.risk_score,
            indicators=result.signals,
            recommendations=result.recommendations,
        )

    def assess_typed(self, text: str) -> LocalHeuristicResult:
        score = 0
        indicators: list[str] = []

        checks = [
            (self.URGENCY, 20, "Creates urgency or fear to rush action."),
            (self.CREDENTIALS, 30, "Requests credentials, OTPs, recovery phrases, or account verification."),
            (self.MONEY, 20, "Mentions money, crypto, rewards, refunds, or investment bait."),
            (self.URL, 15, "Contains links that should be independently verified."),
            (self.SHORTENER, 20, "Uses a URL shortener that can hide the final destination."),
            (self.BRAND_IMPERSONATION, 25, "Contains possible brand impersonation or lookalike wording."),
        ]

        for pattern, weight, message in checks:
            if pattern.search(text):
                score += weight
                indicators.append(message)

        extracted = self.extract_indicators(text)
        for indicator in extracted:
            if indicator.type == "domain" and self._has_suspicious_tld(indicator.value):
                score += 20
                indicators.append(f"Domain uses suspicious or abuse-prone TLD: {indicator.value}")
            if indicator.type == "domain" and self._looks_like_ipfs_or_randomized(indicator.value):
                score += 15
                indicators.append(f"Domain appears randomized or infrastructure-like: {indicator.value}")

        if not indicators:
            indicators.append("No strong phishing indicators found in the submitted text.")

        recommendations = [
            "Do not click links from unsolicited messages.",
            "Open the official website or app manually instead of using provided links.",
            "Never share OTPs, passwords, private keys, or recovery phrases.",
            "Report suspicious Telegram accounts and block repeat senders.",
        ]
        target = self.classify_target(text)
        score = min(score, 100)
        return LocalHeuristicResult(
            indicator=target,
            risk_score=score,
            risk_level=risk_from_score(score),
            signals=indicators,
            extracted_indicators=extracted,
            recommendations=recommendations,
        )

    def classify_target(self, value: str) -> Indicator:
        cleaned = value.strip()
        if self._is_ip(cleaned):
            return Indicator(cleaned, "ip")
        if cleaned.lower().startswith(("http://", "https://", "www.")) and self._is_url(cleaned):
            return Indicator(cleaned, "url")
        if self._is_domain(cleaned):
            return Indicator(cleaned.lower(), "domain")
        return Indicator(cleaned[:300], "message")

    def extract_indicators(self, text: str) -> list[Indicator]:
        indicators: list[Indicator] = []
        seen: set[tuple[IndicatorType, str]] = set()

        for match in self.URL.findall(text):
            value = match.strip(".,)];'")
            if value.startswith("www."):
                value = f"https://{value}"
            self._add_indicator(indicators, seen, Indicator(value, "url"))
            host = urlparse(value).hostname
            if host and not self._is_ip(host):
                self._add_indicator(indicators, seen, Indicator(host.lower(), "domain"))

        for match in self.DOMAIN.findall(text):
            domain = match.strip(".,)];'").lower()
            if not self._is_ip(domain):
                self._add_indicator(indicators, seen, Indicator(domain, "domain"))

        for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            if self._is_ip(token):
                self._add_indicator(indicators, seen, Indicator(token, "ip"))

        return indicators[:10]

    def _add_indicator(
        self,
        indicators: list[Indicator],
        seen: set[tuple[IndicatorType, str]],
        indicator: Indicator,
    ) -> None:
        key = (indicator.type, indicator.value)
        if key not in seen:
            seen.add(key)
            indicators.append(indicator)

    def _is_url(self, value: str) -> bool:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        return bool(parsed.scheme in {"http", "https"} and parsed.netloc and "." in parsed.netloc)

    def _is_domain(self, value: str) -> bool:
        return bool(self.DOMAIN.fullmatch(value.strip().lower()))

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    def _has_suspicious_tld(self, domain: str) -> bool:
        return domain.rsplit(".", 1)[-1].lower() in self.SUSPICIOUS_TLDS

    def _looks_like_ipfs_or_randomized(self, domain: str) -> bool:
        label = domain.split(".", 1)[0]
        has_many_digits = sum(ch.isdigit() for ch in label) >= 4
        long_label = len(label) >= 18
        low_vowels = sum(ch in "aeiou" for ch in label.lower()) <= max(1, len(label) // 8)
        return long_label and (has_many_digits or low_vowels)
