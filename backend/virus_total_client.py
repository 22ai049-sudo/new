from __future__ import annotations

import base64
import os
from typing import Any

import requests


class VirusTotalClient:
    """Authenticated VirusTotal v3 client for IOC enrichment."""

    def __init__(self) -> None:
        self.api_key = os.getenv("VT_API_KEY", "")
        self.base_url = os.getenv("VT_BASE_URL", "https://www.virustotal.com/api/v3")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup_ioc(self, ioc_type: str, value: str) -> dict[str, Any]:
        if not self.enabled:
            return {
                "enabled": False,
                "error": "VirusTotal API key not configured. Set VT_API_KEY.",
                "indicator": {"type": ioc_type, "value": value},
            }

        endpoint = self._ioc_endpoint(ioc_type, value)
        if not endpoint:
            return {
                "enabled": True,
                "error": f"Unsupported IOC type: {ioc_type}",
                "indicator": {"type": ioc_type, "value": value},
            }

        try:
            response = requests.get(
                f"{self.base_url}/{endpoint}",
                headers={"x-apikey": self.api_key},
                timeout=20,
            )
            response.raise_for_status()
            payload = response.json().get("data", {})
            attrs = payload.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            total = malicious + suspicious + harmless + int(stats.get("undetected", 0))
            confidence_boost = min(0.25, (malicious + suspicious) / max(total, 1))
            return {
                "enabled": True,
                "indicator": {"type": ioc_type, "value": value},
                "vt": {
                    "reputation": attrs.get("reputation", 0),
                    "analysis_stats": stats,
                    "categories": attrs.get("categories", {}),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                },
                "threat_label": "malicious" if malicious > 0 else "unknown",
                "confidence_boost": round(confidence_boost, 3),
            }
        except requests.RequestException as exc:
            return {
                "enabled": True,
                "indicator": {"type": ioc_type, "value": value},
                "error": f"VirusTotal lookup failed: {exc}",
            }

    @staticmethod
    def _ioc_endpoint(ioc_type: str, value: str) -> str | None:
        mapping = {
            "ip": f"ip_addresses/{value}",
            "domain": f"domains/{value}",
            "url": f"urls/{VirusTotalClient._url_id(value)}",
            "file_hash": f"files/{value}",
        }
        return mapping.get(ioc_type)

    @staticmethod
    def _url_id(url: str) -> str:
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return encoded
