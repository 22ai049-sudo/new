import React from "react";

export default function AuditLogsViewer({ logs = [] }) {
  return (
    <div className="panel">
      <h3>Audit Trail</h3>
      <p className="muted">Immutable event stream for SOC investigation and compliance.</p>
      <div className="log-container">
        {!logs.length ? <p className="muted">No logs yet.</p> : null}
        {logs.map((log, idx) => (
          <div key={`${log.timestamp || "ts"}-${idx}`} className="log-item">
            <div className="log-head">
              <strong>{log.event_type || "event"}</strong>
              <span className="muted">{log.timestamp || ""}</span>
            </div>
            <pre>{JSON.stringify(log.payload || log, null, 2)}</pre>
          </div>
        ))}
      </div>
    </div>
  );
}
