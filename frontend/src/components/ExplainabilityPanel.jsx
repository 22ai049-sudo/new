import React from "react";

export default function ExplainabilityPanel({ explainability }) {
  if (!explainability) return <div className="panel">No explainability data.</div>;

  return (
    <div className="panel">
      <h3>LLM Explainability</h3>
      <p><strong>Reasoning:</strong> {explainability.llm_reasoning}</p>
      <p><strong>MITRE ATT&CK:</strong> {explainability.mitre_attack_mapping?.join(", ")}</p>
      <p><strong>Confidence:</strong> {Math.round((explainability.confidence_score || 0) * 100)}%</p>
      <p><strong>Risk Severity:</strong> {explainability.risk_severity}</p>
    </div>
  );
}
