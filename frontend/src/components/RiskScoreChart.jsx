import React from "react";

export default function RiskScoreChart({ riskScore = 0 }) {
  const width = Math.max(0, Math.min(100, Math.round(riskScore * 100)));
  return (
    <div className="panel">
      <h3>Risk Score</h3>
      <div style={{ background: "#1f2937", borderRadius: 6, overflow: "hidden" }}>
        <div
          style={{
            width: `${width}%`,
            background: width > 75 ? "#dc2626" : width > 40 ? "#f59e0b" : "#16a34a",
            color: "white",
            textAlign: "center",
            padding: "6px 0",
          }}
        >
          {width}%
        </div>
      </div>
    </div>
  );
}
