import React from "react";

export default function MitigationPanel({ mitigation, validation }) {
  if (!mitigation) {
    return (
      <div className="panel">
        <h3>Mitigation</h3>
        <p className="muted">No mitigation data available.</p>
      </div>
    );
  }

  return (
    <div className="panel">
      <h3>Mitigation Plan</h3>
      <p><span className="label">Strategy</span></p>
      <p>{mitigation.strategy || "N/A"}</p>
      <p><span className="label">ATAVE Verdict</span> {validation?.verdict || "unknown"}</p>

      <div className="cmd-columns">
        <div>
          <h4>Approved Commands</h4>
          <ul className="cmd-list">
            {(mitigation.approved_commands || []).map((cmd) => <li key={cmd}><code>{cmd}</code></li>)}
            {!mitigation.approved_commands?.length ? <li className="muted">None</li> : null}
          </ul>
        </div>

        <div>
          <h4>Rejected Commands</h4>
          <ul className="cmd-list">
            {(mitigation.rejected_commands || []).map((item, idx) => (
              <li key={`${item.command}-${idx}`}><code>{item.command}</code> <span className="muted">({item.reason})</span></li>
            ))}
            {!mitigation.rejected_commands?.length ? <li className="muted">None</li> : null}
          </ul>
        </div>
      </div>
    </div>
  );
}
