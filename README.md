# AI SOC Automation Platform (FastAPI + Redis + Docker Sandbox + Ollama + React)

Production-style, modular SOC automation stack with explainability and safe execution controls.

## Architecture

- **Backend:** FastAPI micro-modules for detection, LLM reasoning, command policy validation (ATAVE), Docker sandbox execution, and audit logging.
- **Orchestration:** **Redis only** for queueing, pub/sub, and incident state.
- **LLM:** Local **Ollama** serving **Mistral 7B**.
- **Sandbox Mitigation:** `docker run --network none --cap-drop ALL` per command.
- **Frontend:** React/Vite analyst dashboard with explainability and audit monitoring.

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

## Frontend Modules

1. `frontend/src/components/AnalystDashboard.jsx`
2. `frontend/src/components/IncidentPanel.jsx`
3. `frontend/src/components/ExplainabilityPanel.jsx`
4. `frontend/src/components/MitigationPanel.jsx`
5. `frontend/src/components/RiskScoreChart.jsx`
6. `frontend/src/components/AuditLogsViewer.jsx`

## Security Features

- Command whitelist enforcement via `CommandVerifier.WHITELIST_PREFIXES`.
- Unsafe command rejection via `CommandVerifier.UNSAFE_KEYWORDS`.
- Sandbox isolation logging in `sandbox_executor.py` under `sandbox_isolation` field.

## Explainability Features

- LLM reasoning display (`llm_reasoning`).
- MITRE ATT&CK mapping (`mitre_attack_mapping`).
- Confidence score (`confidence_score`).
- Risk severity indicator (`risk_severity`).

---

## Installation Steps (Local Dev)

### 1) Prerequisites

- Docker + Docker Compose
- Python 3.11+
- Node.js 20+
- Ollama installed locally (if not using compose service)

### 2) Backend install

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3) Frontend install

```bash
cd frontend
npm install
```

### 4) Redis setup

Option A: Docker

```bash
docker run --name soc-redis -p 6379:6379 -d redis:7-alpine
```

Option B: Use compose (recommended below).

### 5) Ollama setup (Mistral 7B)

```bash
ollama serve
ollama pull mistral:7b
```

If using compose Ollama container:

```bash
docker compose up -d ollama
docker exec -it $(docker ps -qf name=ollama) ollama pull mistral:7b
```

---

## Run Instructions (Without Compose)

### Backend

```bash
cd backend
export REDIS_URL=redis://localhost:6379/0
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=mistral:7b
uvicorn main_api:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend

```bash
cd frontend
export VITE_API_URL=http://localhost:8000
npm run dev -- --host 0.0.0.0 --port 5173
```

Open: `http://localhost:5173`

---

## Docker Setup (Full Stack)

1. Pull/start stack:

```bash
docker compose up -d --build
```

2. Pull model in Ollama service:

```bash
docker exec -it $(docker ps -qf name=ollama) ollama pull mistral:7b
```

3. Access services:

- Frontend: `http://localhost:5173`
- Backend API docs: `http://localhost:8000/docs`
- Redis: `localhost:6379`
- Ollama API: `http://localhost:11434`

---

## API Quick Test

```bash
curl -X POST http://localhost:8000/api/incidents/process \
  -H "Content-Type: application/json" \
  -d '{"id":"inc-1001","source":"suricata","event":"failed login bruteforce from 10.2.2.5","metadata":{"src_ip":"10.2.2.5"}}'
```

## Audit Log Output

- JSONL file: `backend/data/audit_logs.jsonl`
- API endpoint: `GET /api/audit-logs?limit=50`

