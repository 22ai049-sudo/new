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

        severity = "medium"
        confidence = 0.61
        summary = "Suspicious activity detected, analyst review recommended."
        mitre = ["T1087"]

        if any(token in text for token in ["bruteforce", "failed login", "credential stuffing"]):
            severity = "high"
            confidence = 0.87
            summary = "Possible brute-force or credential abuse attempt detected."
            mitre = ["T1110"]
        elif any(token in text for token in ["port scan", "nmap", "scan"]):
            severity = "medium"
            confidence = 0.74
            summary = "Network reconnaissance behavior identified."
            mitre = ["T1595"]

        enrichment = alert.get("metadata", {}).get("enrichment", {}).get("virustotal", {})
        confidence += float(enrichment.get("confidence_boost", 0.0) or 0.0)
        confidence = min(0.99, round(confidence, 3))

        stats = enrichment.get("vt", {}).get("analysis_stats", {}) if isinstance(enrichment, dict) else {}
        malicious_votes = int(stats.get("malicious", 0)) if isinstance(stats, dict) else 0
        if malicious_votes >= 5 and severity != "high":
            severity = "high"
            summary = f"{summary} VirusTotal enrichment indicates confirmed malicious reputation."

        return DetectionResult(
            incident_id=str(alert.get("id", "incident-unknown")),
            summary=summary,
            severity=severity,
            confidence=confidence,
            initial_mitre_mapping=mitre,
        )
