import React from "react";

export default function MitigationPanel({ mitigation, validation }) {
  if (!mitigation) return <div className="panel">No mitigation data.</div>;

  return (
    <div className="panel">
      <h3>Mitigation</h3>
      <p><strong>Strategy:</strong> {mitigation.strategy}</p>
      <p><strong>ATAVE Verdict:</strong> {validation?.verdict}</p>
      <h4>Approved Commands</h4>
      <ul>
        {mitigation.approved_commands?.map((cmd) => <li key={cmd}>{cmd}</li>)}
      </ul>
      <h4>Rejected Commands</h4>
      <ul>
        {mitigation.rejected_commands?.map((item, idx) => (
          <li key={`${item.command}-${idx}`}>{item.command} ({item.reason})</li>
        ))}
      </ul>
    </div>
  );
}
