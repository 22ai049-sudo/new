import React from "react";

export default function RiskScoreChart({ riskScore = 0 }) {
  const score = Math.max(0, Math.min(100, Math.round(riskScore * 100)));
  const status = score >= 75 ? "Critical" : score >= 45 ? "Elevated" : "Controlled";

  return (
    <div className="panel">
      <h3>Risk Severity Indicator</h3>
      <div className="risk-wrap">
        <div className="risk-bar">
          <div
            className="risk-fill"
            style={{
              width: `${score}%`,
              background: score >= 75 ? "#ef4444" : score >= 45 ? "#f59e0b" : "#22c55e",
            }}
          />
        </div>
        <div className="risk-meta">
          <strong>{score}%</strong>
          <span className="muted">{status}</span>
        </div>
      </div>
    </div>
  );
}
