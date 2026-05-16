from __future__ import annotations


def breach_recommendations(breached: bool) -> list[str]:
    if not breached:
        return [
            "Keep using unique passwords for every account.",
            "Enable multi-factor authentication on important accounts.",
            "Stay alert for phishing attempts using your email address.",
        ]
    return [
        "Change passwords on affected services and any account that reused them.",
        "Enable multi-factor authentication, preferably with an authenticator app or security key.",
        "Watch for targeted phishing emails that reference leaked account data.",
        "Use a password manager to generate unique passwords.",
    ]

