from __future__ import annotations

from .models import PipelineOutput


def build_executive_summary(output: PipelineOutput) -> str:
    return (
        f"Classification: {output.reasoning.classification}\n"
        f"Confidence: {output.reasoning.confidence:.2f}\n"
        f"ATAVE Verdict: {output.validation.verdict}\n"
        f"Sandbox Status: {output.sandbox.status}\n"
        f"Risk Score: {output.validation.risk_score:.2f}"
    )
