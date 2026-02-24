from __future__ import annotations

from typing import Any


class MitigationGenerator:
    """Build mitigation plan from deterministic + LLM-proposed actions."""

    def build_plan(self, incident: dict[str, Any], llm_output: dict[str, Any]) -> dict[str, Any]:
        baseline = [
            "iptables -A INPUT -s <malicious_ip> -j DROP",
            "ufw deny from <malicious_ip>",
        ]
        suggested = llm_output.get("suggested_mitigations", [])
        commands = self._unique_preserving_order(baseline + suggested)

        return {
            "incident_id": incident["incident_id"],
            "commands": commands,
            "strategy": "layered network containment and credential hardening",
        }

    @staticmethod
    def _unique_preserving_order(items: list[str]) -> list[str]:
        seen: set[str] = set()
        output: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                output.append(item)
        return output
