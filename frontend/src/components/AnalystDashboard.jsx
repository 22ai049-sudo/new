import React, { useMemo, useState } from "react";
import IncidentPanel from "./IncidentPanel";
import ExplainabilityPanel from "./ExplainabilityPanel";
import MitigationPanel from "./MitigationPanel";
import RiskScoreChart from "./RiskScoreChart";
import AuditLogsViewer from "./AuditLogsViewer";
import IngestionPanel from "./IngestionPanel";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const DEFAULT_ALERT = {
  id: "inc-001",
  source: "suricata",
  event: "failed login bruteforce from 10.10.10.20",
  metadata: { src_ip: "8.8.8.8", sensor: "edge-fw-1", domain: "example.org" },
};

export default function AnalystDashboard() {
  const [alertText, setAlertText] = useState(JSON.stringify(DEFAULT_ALERT, null, 2));
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);

  const headerStats = useMemo(() => {
    const confidence = Math.round((result?.explainability?.confidence_score || 0) * 100);
    const risk = Math.round((result?.atave_validation?.risk_score || 0) * 100);
    const severity = result?.explainability?.risk_severity || "n/a";
    return { confidence, risk, severity };
  }, [result]);

  const processIncident = async () => {
    setError("");
    setLoading(true);

    let parsed;
    try {
      parsed = JSON.parse(alertText);
    } catch {
      setError("Alert JSON is invalid. Please fix syntax and retry.");
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_URL}/api/incidents/process`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsed),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `Request failed with ${res.status}`);
      }

      const data = await res.json();
      setResult(data);

      const logsRes = await fetch(`${API_URL}/api/audit-logs?limit=50`);
      if (logsRes.ok) {
        const logsData = await logsRes.json().catch(() => ({ items: [] }));
        setAuditLogs(logsData.items || []);
      }
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : "Unexpected error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dashboard-root">
      <header className="dashboard-header">
        <div>
          <h1>AI SOC Solver Console</h1>
          <p>Ingest ➜ Enrich ➜ Reason ➜ Validate ➜ Sandbox — one confident analyst workflow</p>
        </div>
        <div className="header-badges">
          <span className="badge">Confidence: {headerStats.confidence}%</span>
          <span className="badge">Risk: {headerStats.risk}%</span>
          <span className="badge">Severity: {String(headerStats.severity).toUpperCase()}</span>
        </div>
      </header>

      <section className="panel">
        <h3>Alert Intake</h3>
        <p className="muted">Provide normalized events with IOC fields (`src_ip`, `domain`, `url`, `sha256`) for VT-auth enrichment.</p>
        <textarea
          rows={11}
          className="editor"
          value={alertText}
          onChange={(e) => setAlertText(e.target.value)}
          aria-label="alert-json-editor"
        />
        <div className="actions-row">
          <button className="primary-btn" onClick={processIncident} disabled={loading}>
            {loading ? "Solving Incident…" : "Run SOC Solver"}
          </button>
          <button className="secondary-btn" onClick={() => setAlertText(JSON.stringify(DEFAULT_ALERT, null, 2))}>
            Load Gold Sample
          </button>
        </div>
        {error ? <p className="error-text">{error}</p> : null}
      </section>

      <section className="grid-2">
        <IngestionPanel ingestion={result?.ingestion} />
        <RiskScoreChart riskScore={result?.atave_validation?.risk_score || 0} />
      </section>

      <section className="grid-2">
        <IncidentPanel incident={result?.incident} />
        <ExplainabilityPanel explainability={result?.explainability} />
      </section>

      <MitigationPanel mitigation={result?.mitigation} validation={result?.atave_validation} />
      <AuditLogsViewer logs={auditLogs} />
    </div>
  );
}
