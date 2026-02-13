from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Alert:
    source: str
    timestamp: str
    event: str
    severity: str
    src_ip: str = ""
    dst_asset: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    threat_detected: bool
    detection_score: float
    model_name: str
    indicators: List[str]


@dataclass
class ReasoningResult:
    classification: str
    mitre_techniques: List[str]
    summary: str
    recommended_actions: List[str]
    confidence: float
    reasoning_chain: List[str]
    evidence: List[str] = field(default_factory=list)


@dataclass
class ResolutionPlan:
    mode: str
    resolved_actions: List[str]
    resolution_notes: str


@dataclass
class ValidationResult:
    verdict: str
    safe_actions: List[str]
    blocked_actions: List[str]
    risk_score: float
    rationale: str


@dataclass
class SandboxResult:
    executed: bool
    execution_log: List[str]
    impact_score: float
    status: str


@dataclass
class PipelineOutput:
    alert: Alert
    detection: DetectionResult
    reasoning: ReasoningResult
    resolution: ResolutionPlan
    validation: ValidationResult
    sandbox: SandboxResult

    def as_dict(self) -> Dict[str, Any]:
        return {
            "alert": self.alert.__dict__,
            "detection": self.detection.__dict__,
            "reasoning": self.reasoning.__dict__,
            "resolution": self.resolution.__dict__,
            "validation": self.validation.__dict__,
            "sandbox": self.sandbox.__dict__,
        }
