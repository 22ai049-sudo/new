import React from "react";

export default function AuditLogsViewer({ logs = [] }) {
  return (
    <div className="panel">
      <h3>Audit Logs</h3>
      <div style={{ maxHeight: 240, overflowY: "auto", background: "#0b1220", padding: 10 }}>
        {logs.map((log, idx) => (
          <pre key={idx} style={{ whiteSpace: "pre-wrap", color: "#d1d5db" }}>
            {JSON.stringify(log, null, 2)}
          </pre>
        ))}
      </div>
    </div>
  );
}
