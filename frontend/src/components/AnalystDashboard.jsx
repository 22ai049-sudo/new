import React, { useState } from "react";
import IncidentPanel from "./IncidentPanel";
import ExplainabilityPanel from "./ExplainabilityPanel";
import MitigationPanel from "./MitigationPanel";
import RiskScoreChart from "./RiskScoreChart";
import AuditLogsViewer from "./AuditLogsViewer";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function AnalystDashboard() {
  const [alert, setAlert] = useState({
    id: "inc-001",
    source: "suricata",
    event: "failed login bruteforce from 10.10.10.20",
    metadata: { src_ip: "10.10.10.20" },
  });
  const [result, setResult] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);

  const processIncident = async () => {
    const res = await fetch(`${API_URL}/api/incidents/process`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(alert),
    });
    const data = await res.json();
    setResult(data);

    const logsRes = await fetch(`${API_URL}/api/audit-logs?limit=20`);
    const logsData = await logsRes.json();
    setAuditLogs(logsData.items || []);
  };

  return (
    <div style={{ padding: 20, fontFamily: "Inter, sans-serif", background: "#111827", color: "#f9fafb" }}>
      <h1>AI SOC Analyst Dashboard</h1>
      <div className="panel">
        <h3>Submit Alert</h3>
        <textarea
          rows={4}
          style={{ width: "100%" }}
          value={JSON.stringify(alert, null, 2)}
          onChange={(e) => setAlert(JSON.parse(e.target.value))}
        />
        <button onClick={processIncident}>Process Incident</button>
      </div>

      <IncidentPanel incident={result?.incident} />
      <ExplainabilityPanel explainability={result?.explainability} />
      <MitigationPanel mitigation={result?.mitigation} validation={result?.atave_validation} />
      <RiskScoreChart riskScore={result?.atave_validation?.risk_score || 0} />
      <AuditLogsViewer logs={auditLogs} />
    </div>
  );
}
