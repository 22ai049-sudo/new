import React from "react";

function severityClass(severity) {
  const normalized = String(severity || "unknown").toLowerCase();
  if (normalized === "critical") return "sev-critical";
  if (normalized === "high") return "sev-high";
  if (normalized === "medium") return "sev-medium";
  return "sev-low";
}

export default function IncidentPanel({ incident }) {
  if (!incident) {
    return (
      <div className="panel">
        <h3>Incident</h3>
        <p className="muted">No incident processed yet.</p>
      </div>
    );
  }

  return (
    <div className="panel">
      <h3>Incident Overview</h3>
      <div className="kv-grid">
        <div><span className="label">Incident ID</span><span>{incident.incident_id}</span></div>
        <div><span className="label">Severity</span><span className={`severity-chip ${severityClass(incident.severity)}`}>{incident.severity}</span></div>
      </div>
      <p><span className="label">Summary</span></p>
      <p>{incident.summary}</p>
    </div>
  );
}
