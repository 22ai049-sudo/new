from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DetectionResult:
    incident_id: str
    summary: str
    severity: str
    confidence: float
    initial_mitre_mapping: list[str]


class Detector:
    """Rule-assisted detector for normalizing alerts into SOC incidents."""

    def analyze(self, alert: dict[str, Any]) -> DetectionResult:
        source = str(alert.get("source", "unknown"))
        event = str(alert.get("event", ""))
        text = f"{source} {event}".lower()

        if any(token in text for token in ["bruteforce", "failed login", "credential stuffing"]):
            return DetectionResult(
                incident_id=str(alert.get("id", "incident-unknown")),
                summary="Possible brute-force or credential abuse attempt detected.",
                severity="high",
                confidence=0.87,
                initial_mitre_mapping=["T1110"],
            )

        if any(token in text for token in ["port scan", "nmap", "scan"]):
            return DetectionResult(
                incident_id=str(alert.get("id", "incident-unknown")),
                summary="Network reconnaissance behavior identified.",
                severity="medium",
                confidence=0.74,
                initial_mitre_mapping=["T1595"],
            )

        return DetectionResult(
            incident_id=str(alert.get("id", "incident-unknown")),
            summary="Suspicious activity detected, analyst review recommended.",
            severity="medium",
            confidence=0.61,
            initial_mitre_mapping=["T1087"],
        )
