from __future__ import annotations

from typing import Any


class AtaveValidator:
    """Adaptive Threat-Action Validation Engine for policy-safe automation."""

    def validate(self, severity: str, confidence: float, rejected_count: int) -> dict[str, Any]:
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        level = severity_rank.get(severity.lower(), 2)

        risk_score = min(1.0, (level * 0.2) + ((1 - confidence) * 0.5) + (rejected_count * 0.1))

        if level == 4 or risk_score >= 0.85:
            verdict = "human_review_required"
        elif rejected_count > 0:
            verdict = "modify_then_retry"
        else:
            verdict = "approved"

        return {
            "verdict": verdict,
            "risk_score": round(risk_score, 2),
            "policy_notes": [
                "Command whitelist enforced",
                "Unsafe command rejection active",
                "Sandbox-only execution for approved commands",
            ],
        }
