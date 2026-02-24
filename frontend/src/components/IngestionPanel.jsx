import React from "react";

export default function IngestionPanel({ ingestion }) {
  const vt = ingestion?.virustotal || {};
  const stats = vt?.vt?.analysis_stats || {};
  const ioc = ingestion?.ioc;
  const status = vt?.enabled ? (vt?.error ? "degraded" : "active") : "disabled";

  return (
    <section className="panel">
      <h3>Threat Intel Ingestion</h3>
      <p className="muted">Authenticated VirusTotal enrichment is fused before model reasoning.</p>
      <div className="kv-grid">
        <div><span className="label">IOC</span><span>{ioc ? `${ioc.type}: ${ioc.value}` : "Not found"}</span></div>
        <div><span className="label">VT Status</span><span className={`status-${status}`}>{status.toUpperCase()}</span></div>
        <div><span className="label">Confidence Boost</span><span>{Math.round((vt?.confidence_boost || 0) * 100)}%</span></div>
        <div><span className="label">Threat Label</span><span>{vt?.threat_label || "unknown"}</span></div>
      </div>

      <div className="chip-row top-gap">
        <span className="chip">malicious: {stats.malicious || 0}</span>
        <span className="chip">suspicious: {stats.suspicious || 0}</span>
        <span className="chip">harmless: {stats.harmless || 0}</span>
        <span className="chip">undetected: {stats.undetected || 0}</span>
      </div>

      {vt?.error ? <p className="error-text">{vt.error}</p> : null}
    </section>
  );
}
