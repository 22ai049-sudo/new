from __future__ import annotations

from typing import Any

from virus_total_client import VirusTotalClient


class DataIngestionService:
    """Normalizes incoming alerts and enriches them with VirusTotal intel."""

    def __init__(self) -> None:
        self.vt = VirusTotalClient()

    def ingest_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        normalized = {
            "id": str(alert.get("id", "incident-unknown")),
            "source": str(alert.get("source", "unknown")),
            "event": str(alert.get("event", "")),
            "metadata": alert.get("metadata", {}) if isinstance(alert.get("metadata"), dict) else {},
        }

        ioc = self._extract_ioc(normalized)
        enrichment = self.vt.lookup_ioc(ioc["type"], ioc["value"]) if ioc else {
            "enabled": self.vt.enabled,
            "error": "No IOC available for VirusTotal lookup",
        }

        normalized["metadata"]["enrichment"] = {
            "ioc": ioc,
            "virustotal": enrichment,
        }
        return normalized

    @staticmethod
    def _extract_ioc(alert: dict[str, Any]) -> dict[str, str] | None:
        metadata = alert.get("metadata", {})
        if metadata.get("sha256"):
            return {"type": "file_hash", "value": str(metadata["sha256"]).strip()}
        if metadata.get("url"):
            return {"type": "url", "value": str(metadata["url"]).strip()}
        if metadata.get("domain"):
            return {"type": "domain", "value": str(metadata["domain"]).strip()}
        if metadata.get("src_ip"):
            return {"type": "ip", "value": str(metadata["src_ip"]).strip()}
        return None
