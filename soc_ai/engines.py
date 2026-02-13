from __future__ import annotations

from datetime import datetime, timezone
from random import uniform
from typing import List

from .knowledge import MITRE_KNOWLEDGE, POLICY_RULES
from .models import (
    Alert,
    DetectionResult,
    PipelineOutput,
    ReasoningResult,
    ResolutionPlan,
    SandboxResult,
    ValidationResult,
)


class AlertIngestionEngine:
    def normalize(self, raw: dict) -> Alert:
        ts = raw.get("timestamp") or datetime.now(timezone.utc).isoformat()
        metadata = raw.get("metadata") or {}
        return Alert(
            source=raw.get("source", "unknown"),
            timestamp=ts,
            event=raw.get("event", "unknown_event"),
            severity=str(raw.get("severity", "medium")).lower(),
            src_ip=raw.get("src_ip", metadata.get("src_ip", "")),
            dst_asset=raw.get("dst_asset", metadata.get("dst_asset", "")),
            metadata=metadata,
        )


class ThreatDetectionMLEngine:
    """A lightweight ML-style scorer for threat detection without external deps."""

    WEIGHTS = {
        "brute": 0.32,
        "credential": 0.28,
        "phish": 0.27,
        "scan": 0.24,
        "recon": 0.22,
        "ransom": 0.36,
        "malware": 0.35,
        "c2": 0.33,
        "beacon": 0.31,
        "lateral": 0.25,
    }

    def detect(self, alert: Alert) -> DetectionResult:
        tokens = alert.event.lower().split()
        score = 0.08
        indicators: List[str] = []

        for token in tokens:
            clean = token.strip(".,:;!?()[]{}")
            if clean in self.WEIGHTS:
                score += self.WEIGHTS[clean]
                indicators.append(clean)

        severity_boost = {"low": 0.02, "medium": 0.08, "high": 0.15, "critical": 0.22}.get(alert.severity, 0.05)
        score = min(0.99, score + severity_boost)

        return DetectionResult(
            threat_detected=score >= 0.4,
            detection_score=score,
            model_name="ThreatLite-v1 (heuristic-ml)",
            indicators=sorted(set(indicators)),
        )


class LLMReasoningEngine:
    def interpret(self, alert: Alert) -> ReasoningResult:
        event = alert.event.lower()
        if "brute" in event or "credential" in event:
            return self._build(
                "Credential Access Attempt",
                ["T1110", "T1078"],
                "Multiple suspicious authentication attempts indicate probable brute-force activity.",
                [
                    "Block source IP on edge firewall for 30 minutes",
                    "Enforce MFA challenge for affected accounts",
                    "Trigger password reset for targeted identities",
                ],
                0.92,
            )
        if "phish" in event or "mail" in event:
            return self._build(
                "Phishing / Initial Access",
                ["T1566"],
                "Email-based lure pattern suggests initial access attempt through phishing.",
                [
                    "Quarantine suspicious email artifacts",
                    "Revoke active user sessions",
                    "Force credential reset for impacted mailbox",
                ],
                0.88,
            )
        if "scan" in event or "recon" in event:
            return self._build(
                "Reconnaissance",
                ["T1595"],
                "Host and port probing activity indicates recon stage before exploitation.",
                [
                    "Rate-limit source traffic",
                    "Block scanner subnet in perimeter ACL",
                    "Increase IDS sensitivity for source IP",
                ],
                0.82,
            )

        return self._build(
            "Suspicious Activity",
            ["T1059"],
            "Anomalous telemetry requires analyst confirmation and host triage.",
            [
                "Collect endpoint process tree",
                "Isolate suspected host in containment VLAN",
                "Escalate to Tier-2 SOC analyst",
            ],
            0.74,
        )

    def _build(
        self,
        classification: str,
        mitre_codes: List[str],
        summary: str,
        actions: List[str],
        confidence: float,
    ) -> ReasoningResult:
        reasoning_chain = [
            "Normalize incoming alert and extract entity context",
            "Map event semantics to ATT&CK tactics and known behavior",
            "Generate ranked and actionable mitigation recommendations",
        ]
        return ReasoningResult(
            classification=classification,
            mitre_techniques=mitre_codes,
            summary=summary,
            recommended_actions=actions,
            confidence=confidence,
            reasoning_chain=reasoning_chain,
        )


class RAGContextEngine:
    def enrich(self, reasoning: ReasoningResult) -> ReasoningResult:
        evidence = [MITRE_KNOWLEDGE.get(code, "No evidence found") for code in reasoning.mitre_techniques]
        reasoning.evidence = evidence
        return reasoning


class LLMResolverEngine:
    """Transforms recommendations into concrete remediation playbook steps."""

    def resolve(self, reasoning: ReasoningResult, auto_resolve: bool) -> ResolutionPlan:
        if not auto_resolve:
            return ResolutionPlan(
                mode="manual",
                resolved_actions=reasoning.recommended_actions,
                resolution_notes="Manual mode enabled: analyst can review and execute recommendations.",
            )

        resolved = [
            f"[AUTO-PLAYBOOK] {action} | owner=SOAR-bot | timeout=15m"
            for action in reasoning.recommended_actions
        ]
        return ResolutionPlan(
            mode="auto",
            resolved_actions=resolved,
            resolution_notes="Auto mode enabled: generated deterministic playbook actions from LLM guidance.",
        )


class ATAVEValidationEngine:
    def validate(self, alert: Alert, actions: List[str]) -> ValidationResult:
        blocked_keywords = POLICY_RULES["blocked_keywords"]
        blocked, safe = [], []
        for action in actions:
            if any(word in action.lower() for word in blocked_keywords):
                blocked.append(action)
            else:
                safe.append(action)

        base_risk = {"low": 0.2, "medium": 0.45, "high": 0.67, "critical": 0.85}.get(alert.severity, 0.5)
        risk_score = min(1.0, base_risk + uniform(0.02, 0.08))

        if blocked:
            return ValidationResult(
                verdict="Reject",
                safe_actions=safe,
                blocked_actions=blocked,
                risk_score=risk_score,
                rationale="One or more actions violate destructive-action policy.",
            )

        if alert.severity in POLICY_RULES["require_human_review_severity"]:
            return ValidationResult(
                verdict="Require Human Review",
                safe_actions=safe,
                blocked_actions=blocked,
                risk_score=risk_score,
                rationale="Critical incidents require human approval before execution.",
            )

        if risk_score > POLICY_RULES["max_auto_risk"]:
            return ValidationResult(
                verdict="Modify",
                safe_actions=safe[:2],
                blocked_actions=safe[2:],
                risk_score=risk_score,
                rationale="Risk threshold exceeded; reduce blast radius with partial actions.",
            )

        return ValidationResult(
            verdict="Approve",
            safe_actions=safe,
            blocked_actions=[],
            risk_score=risk_score,
            rationale="Actions passed ATAVE checks and are safe for sandbox execution.",
        )


class SandboxExecutionEngine:
    def execute(self, validation: ValidationResult) -> SandboxResult:
        if validation.verdict in {"Reject", "Require Human Review"}:
            return SandboxResult(
                executed=False,
                execution_log=["Execution skipped based on validation verdict."],
                impact_score=0.0,
                status="Skipped",
            )

        logs = [f"[OK] Simulated action: {action}" for action in validation.safe_actions]
        if validation.blocked_actions:
            logs.extend([f"[BLOCKED] {action}" for action in validation.blocked_actions])

        return SandboxResult(
            executed=True,
            execution_log=logs,
            impact_score=max(0.1, 1 - validation.risk_score),
            status="Completed in isolated sandbox",
        )


class SOCPipeline:
    def __init__(self) -> None:
        self.ingestion = AlertIngestionEngine()
        self.detector = ThreatDetectionMLEngine()
        self.reasoning = LLMReasoningEngine()
        self.rag = RAGContextEngine()
        self.resolver = LLMResolverEngine()
        self.atave = ATAVEValidationEngine()
        self.sandbox = SandboxExecutionEngine()

    def run(self, raw_alert: dict, auto_resolve: bool = True) -> PipelineOutput:
        alert = self.ingestion.normalize(raw_alert)
        detection = self.detector.detect(alert)
        reasoning = self.reasoning.interpret(alert)
        reasoning = self.rag.enrich(reasoning)
        resolution = self.resolver.resolve(reasoning, auto_resolve=auto_resolve)
        validation = self.atave.validate(alert, resolution.resolved_actions)
        sandbox = self.sandbox.execute(validation)
        return PipelineOutput(
            alert=alert,
            detection=detection,
            reasoning=reasoning,
            resolution=resolution,
            validation=validation,
            sandbox=sandbox,
        )
