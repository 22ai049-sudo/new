from __future__ import annotations

import json
import os
from typing import Any

import requests


class OllamaEngine:
    """Local Ollama integration targeting Mistral 7B."""

    def __init__(self) -> None:
        self.base_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "mistral:7b")

    def generate_analysis(self, incident: dict[str, Any]) -> dict[str, Any]:
        prompt = self._build_prompt(incident)
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
            },
            timeout=60,
        )
        response.raise_for_status()
        raw = response.json().get("response", "{}")
        parsed = json.loads(raw)
        return {
            "reasoning": parsed.get("reasoning", "No reasoning returned by LLM."),
            "mitre_attack_mapping": parsed.get("mitre_attack_mapping", []),
            "confidence_score": float(parsed.get("confidence_score", 0.5)),
            "risk_severity": parsed.get("risk_severity", incident.get("severity", "medium")),
            "suggested_mitigations": parsed.get("suggested_mitigations", []),
        }

    def _build_prompt(self, incident: dict[str, Any]) -> str:
        return (
            "You are a SOC co-pilot. Return strict JSON with keys: reasoning, "
            "mitre_attack_mapping (array), confidence_score (0-1), risk_severity, "
            "suggested_mitigations (array of shell commands).\n"
            f"Incident data: {json.dumps(incident)}"
        )
