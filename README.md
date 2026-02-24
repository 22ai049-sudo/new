# AI SOC Automation Platform (FastAPI + Redis + Docker Sandbox + Ollama + React)

Production-style SOC automation stack with authenticated data ingestion, VirusTotal enrichment, explainable LLM triage, and safe sandboxed mitigation.

## New: Authenticated Data Ingestion (VirusTotal)

The ingestion stage now runs **before detection/LLM** and enriches alerts with IOC intelligence from VirusTotal v3.

- Endpoint: `POST /api/incidents/ingest` (preview enrichment only)
- Processing pipeline: `POST /api/incidents/process` now auto-runs ingestion first
- IOC priority: `sha256` → `url` → `domain` → `src_ip`
- Auth: set `VT_API_KEY` in backend environment

### Required env vars

```bash
export VT_API_KEY=<your_virustotal_api_key>
export VT_BASE_URL=https://www.virustotal.com/api/v3
export REDIS_URL=redis://localhost:6379/0
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=mistral:7b
```

## Architecture

- **Backend:** FastAPI modules for ingestion, detection, LLM reasoning, command policy validation, ATAVE risk gating, Docker sandbox execution, and audit logging.
- **Orchestration:** **Redis only** for queueing, pub/sub, and incident state.
- **LLM:** Local **Ollama** serving **Mistral 7B**.
- **Frontend:** React/Vite analyst console with SOC solver workflow and threat-intel panel.

## Backend Modules

1. `backend/detector.py`
2. `backend/redis_client.py`
3. `backend/llm_engine.py`
4. `backend/mitigation_generator.py`
5. `backend/command_verifier.py`
6. `backend/atave_validator.py`
7. `backend/sandbox_executor.py`
8. `backend/audit_logger.py`
9. `backend/pipeline_orchestrator.py`
10. `backend/main_api.py`
11. `backend/data_ingestion.py`
12. `backend/virus_total_client.py`

## Frontend Modules

- `frontend/src/components/AnalystDashboard.jsx`
- `frontend/src/components/IngestionPanel.jsx`
- `frontend/src/components/IncidentPanel.jsx`
- `frontend/src/components/ExplainabilityPanel.jsx`
- `frontend/src/components/MitigationPanel.jsx`
- `frontend/src/components/RiskScoreChart.jsx`
- `frontend/src/components/AuditLogsViewer.jsx`

## Installation & Run

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main_api:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend

```bash
cd frontend
npm install
export VITE_API_URL=http://localhost:8000
npm run dev -- --host 0.0.0.0 --port 5173
```

## Docker Setup

```bash
docker compose up -d --build
```

Then pull model:

```bash
docker exec -it $(docker ps -qf name=ollama) ollama pull mistral:7b
```

## Redis Setup

```bash
docker run --name soc-redis -p 6379:6379 -d redis:7-alpine
```

## Ollama Setup

```bash
ollama serve
ollama pull mistral:7b
```

## API Examples

### Ingestion preview

```bash
curl -X POST http://localhost:8000/api/incidents/ingest \
  -H "Content-Type: application/json" \
  -d '{"id":"inc-vt-1","source":"edr","event":"suspicious outbound connection","metadata":{"domain":"example.org"}}'
```

### Full processing

```bash
curl -X POST http://localhost:8000/api/incidents/process \
  -H "Content-Type: application/json" \
  -d '{"id":"inc-1001","source":"suricata","event":"failed login bruteforce","metadata":{"src_ip":"8.8.8.8"}}'
```
