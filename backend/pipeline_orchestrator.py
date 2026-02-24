from __future__ import annotations

from typing import Any

from atave_validator import AtaveValidator
from audit_logger import AuditLogger
from command_verifier import CommandVerifier
from data_ingestion import DataIngestionService
from detector import Detector
from llm_engine import OllamaEngine
from mitigation_generator import MitigationGenerator
from redis_client import RedisClient
from sandbox_executor import SandboxExecutor


class PipelineOrchestrator:
    def __init__(self) -> None:
        self.redis = RedisClient()
        self.ingestion = DataIngestionService()
        self.detector = Detector()
        self.llm = OllamaEngine()
        self.mitigation_generator = MitigationGenerator()
        self.command_verifier = CommandVerifier()
        self.atave = AtaveValidator()
        self.sandbox = SandboxExecutor()
        self.audit = AuditLogger(output_file="backend/data/audit_logs.jsonl")

    def process_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        self.audit.write("alert_received", alert)
        enriched_alert = self.ingestion.ingest_alert(alert)
        self.audit.write("ingestion_completed", enriched_alert)
        self.redis.push_queue("soc:alerts", enriched_alert)

        detection = self.detector.analyze(enriched_alert)
        incident = {
            "incident_id": detection.incident_id,
            "summary": detection.summary,
            "severity": detection.severity,
            "confidence": detection.confidence,
            "initial_mitre_mapping": detection.initial_mitre_mapping,
            "raw_alert": enriched_alert,
        }
        self.audit.write("detection_completed", incident)

        llm_output = self.llm.generate_analysis(incident)
        self.audit.write("llm_analysis_completed", llm_output)

        mitigation = self.mitigation_generator.build_plan(incident, llm_output)
        verification = self.command_verifier.verify(mitigation["commands"])
        atave = self.atave.validate(
            severity=llm_output.get("risk_severity", incident["severity"]),
            confidence=llm_output.get("confidence_score", detection.confidence),
            rejected_count=len(verification.rejected),
        )

        sandbox_result = {"executed_commands": 0, "sandbox_logs": []}
        if atave["verdict"] in {"approved", "modify_then_retry"} and verification.approved:
            sandbox_result = self.sandbox.execute(verification.approved)
            self.audit.write("sandbox_execution", sandbox_result)

        result = {
            "ingestion": enriched_alert.get("metadata", {}).get("enrichment", {}),
            "incident": incident,
            "explainability": {
                "llm_reasoning": llm_output.get("reasoning"),
                "mitre_attack_mapping": llm_output.get("mitre_attack_mapping", detection.initial_mitre_mapping),
                "confidence_score": llm_output.get("confidence_score", detection.confidence),
                "risk_severity": llm_output.get("risk_severity", incident["severity"]),
            },
            "mitigation": {
                "strategy": mitigation["strategy"],
                "approved_commands": verification.approved,
                "rejected_commands": verification.rejected,
            },
            "atave_validation": atave,
            "sandbox_execution": sandbox_result,
        }

        self.redis.set_json(f"soc:incident:{detection.incident_id}", result, ttl_seconds=3600)
        self.redis.publish("soc:events", {"incident_id": detection.incident_id, "status": "processed"})
        self.audit.write("incident_processed", result)
        return result
