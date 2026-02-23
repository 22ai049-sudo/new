import React from "react";

export default function IncidentPanel({ incident }) {
  if (!incident) return <div className="panel">No incident processed yet.</div>;

  return (
    <div className="panel">
      <h3>Incident</h3>
      <p><strong>ID:</strong> {incident.incident_id}</p>
      <p><strong>Severity:</strong> {incident.severity}</p>
      <p><strong>Summary:</strong> {incident.summary}</p>
    </div>
  );
}
