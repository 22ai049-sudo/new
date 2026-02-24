import React from "react";

export default function ExplainabilityPanel({ explainability }) {
  if (!explainability) {
    return (
      <div className="panel">
        <h3>LLM Explainability</h3>
        <p className="muted">No explainability data available.</p>
      </div>
    );
  }

  const mitre = explainability.mitre_attack_mapping || [];
  const confidence = Math.round((explainability.confidence_score || 0) * 100);

  return (
    <div className="panel">
      <h3>LLM Explainability</h3>
      <p><span className="label">Reasoning</span></p>
      <p>{explainability.llm_reasoning || "N/A"}</p>
      <p><span className="label">MITRE ATT&CK Mapping</span></p>
      <div className="chip-row">
        {mitre.length ? mitre.map((item) => <span key={item} className="chip">{item}</span>) : <span className="muted">No mapping</span>}
      </div>
      <div className="kv-grid">
        <div><span className="label">Confidence</span><span>{confidence}%</span></div>
        <div><span className="label">Risk Severity</span><span>{explainability.risk_severity || "unknown"}</span></div>
      </div>
    </div>
  );
}
