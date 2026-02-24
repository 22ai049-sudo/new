from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from audit_logger import AuditLogger
from data_ingestion import DataIngestionService
from pipeline_orchestrator import PipelineOrchestrator
from redis_client import RedisClient

app = FastAPI(title="AI SOC Automation Platform", version="1.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = PipelineOrchestrator()
audit = AuditLogger(output_file="backend/data/audit_logs.jsonl")
redis_client = RedisClient()
ingestion = DataIngestionService()


class AlertPayload(BaseModel):
    id: str = Field(..., description="Unique alert ID")
    source: str
    event: str
    metadata: dict = Field(default_factory=dict)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/incidents/ingest")
def ingest_incident(alert: AlertPayload) -> dict:
    return ingestion.ingest_alert(alert.model_dump())


@app.post("/api/incidents/process")
def process_incident(alert: AlertPayload) -> dict:
    try:
        return orchestrator.process_alert(alert.model_dump())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict:
    data = redis_client.get_json(f"soc:incident:{incident_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Incident not found")
    return data


@app.get("/api/audit-logs")
def get_audit_logs(limit: int = 50) -> dict:
    return {"items": audit.tail(max_lines=limit)}
