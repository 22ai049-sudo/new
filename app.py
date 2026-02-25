from __future__ import annotations

import json
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from soc_ai.engines import SOCPipeline


CSS = """
body { font-family: Inter, system-ui, Arial, sans-serif; background: #0b1220; color: #e8eefc; margin: 0; }
.container { max-width: 1200px; margin: 20px auto; padding: 20px; }
.card { background: #121a2b; border: 1px solid #23314f; border-radius: 14px; padding: 18px; margin-bottom: 14px; box-shadow: 0 8px 24px rgba(0,0,0,.18); }
.grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 14px; }
.grid-4 { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 12px; }
.metric { background:#0f1728;border:1px solid #2a3a5d;border-radius:12px;padding:12px; }
.metric .label { color:#9eb0d9;font-size:12px; }
.metric .value { font-size:20px; font-weight:700; margin-top:4px; }
label { font-size: 13px; color: #b9c7e6; display: block; margin-bottom: 6px; }
input, select, textarea { width: 100%; background: #0f1728; color: #e8eefc; border: 1px solid #2a3a5d; border-radius: 10px; padding: 10px; }
button { background: linear-gradient(90deg,#2865f7,#00b5d8); color: white; border: none; padding: 12px 16px; border-radius: 10px; font-weight: 600; cursor: pointer; }
.badge { display: inline-block; padding: 6px 10px; border-radius: 999px; background: #20335f; font-size: 12px; margin-right: 8px; }
pre, .panel { background: #0f1728; border: 1px solid #2a3a5d; border-radius: 10px; padding: 12px; overflow: auto; }
.small { color: #a9b6d4; font-size: 13px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { border-bottom: 1px solid #27365a; padding: 8px; text-align:left; }
"""


def _history_table(history: list[dict]) -> str:
    rows = "".join(
        f"<tr><td>{h['time']}</td><td>{h['src']}</td><td>{h['severity']}</td><td>{h['class']}</td><td>{h['verdict']}</td><td>{h['score']:.2f}</td></tr>"
        for h in reversed(history[-8:])
    )
    if not rows:
        rows = "<tr><td colspan='6'>No incidents processed yet.</td></tr>"
    return f"""
    <table>
      <thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Class</th><th>ATAVE</th><th>Detect Score</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    """


def render_page(result_json: str = "{}", info: str = "", metrics: dict | None = None, history_html: str = "") -> str:
    metrics = metrics or {"threat": "-", "score": "-", "verdict": "-", "mode": "-"}
    return f"""
<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>AI SOC Copilot</title>
  <style>{CSS}</style>
</head>
<body>
  <div class='container'>
    <div class='card'>
      <h1>🛡️ AI SOC Copilot Dashboard</h1>
      <p class='small'>Automatic threat detection + LLM analysis + ML risk validation + auto remediation playbooks.</p>
      <span class='badge'>Auto Threat Detection</span>
      <span class='badge'>LLM Analysis</span>
      <span class='badge'>ATAVE Safety</span>
      <span class='badge'>Auto Resolution</span>
    </div>

    <div class='card grid-4'>
      <div class='metric'><div class='label'>Threat Detected</div><div class='value'>{metrics['threat']}</div></div>
      <div class='metric'><div class='label'>Detection Score</div><div class='value'>{metrics['score']}</div></div>
      <div class='metric'><div class='label'>ATAVE Verdict</div><div class='value'>{metrics['verdict']}</div></div>
      <div class='metric'><div class='label'>Resolver Mode</div><div class='value'>{metrics['mode']}</div></div>
    </div>

    <div class='grid-2'>
      <form method='post' class='card'>
        <h2>Live Alert Input</h2>
        <div class='grid-2'>
          <div><label>Source</label><select name='source'><option>suricata</option><option>zeek</option><option>siem</option><option>syslog</option></select></div>
          <div><label>Severity</label><select name='severity'><option>low</option><option selected>medium</option><option>high</option><option>critical</option></select></div>
          <div><label>Source IP</label><input name='src_ip' value='10.10.10.44' /></div>
          <div><label>Destination Asset</label><input name='dst_asset' value='prod-auth-server-01' /></div>
        </div>
        <div style='margin-top:12px'><label>Event</label><textarea name='event' rows='3'>Repeated credential brute-force attempts on SSH with lockout bursts</textarea></div>
        <div style='margin-top:10px'><label><input type='checkbox' name='auto_resolve' checked/> Enable Auto-Resolve Playbook</label></div>
        <div style='margin-top: 12px;'><button type='submit'>Analyze & Resolve Threat</button></div>
      </form>

      <div class='card'>
        <h2>Incident Feed</h2>
        {history_html}
      </div>
    </div>

    <div class='card'>
      <h2>Explainability + Raw Output</h2>
      <p class='small'>{info}</p>
      <pre>{result_json}</pre>
    </div>
  </div>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    pipeline = SOCPipeline()
    history: list[dict] = []

    def _send_html(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        self._send_html(
            render_page(
                info="Submit an alert to automatically detect, analyze, and optionally auto-resolve.",
                history_html=_history_table(self.history),
            )
        )

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
        fields = parse_qs(body)

        auto_resolve = fields.get("auto_resolve", [""])[0] == "on"

        raw_alert = {
            "source": fields.get("source", ["siem"])[0],
            "severity": fields.get("severity", ["medium"])[0],
            "event": fields.get("event", ["unknown"])[0],
            "src_ip": fields.get("src_ip", [""])[0],
            "dst_asset": fields.get("dst_asset", [""])[0],
            "metadata": {"ui": "dashboard-v2"},
        }

        output = self.pipeline.run(raw_alert, auto_resolve=auto_resolve).as_dict()

        self.history.append(
            {
                "time": datetime.utcnow().strftime("%H:%M:%S"),
                "src": output["alert"]["source"],
                "severity": output["alert"]["severity"],
                "class": output["reasoning"]["classification"],
                "verdict": output["validation"]["verdict"],
                "score": output["detection"]["detection_score"],
            }
        )

        metrics = {
            "threat": "YES" if output["detection"]["threat_detected"] else "NO",
            "score": f"{output['detection']['detection_score']:.2f}",
            "verdict": output["validation"]["verdict"],
            "mode": output["resolution"]["mode"],
        }

        self._send_html(
            render_page(
                result_json=json.dumps(output, indent=2),
                info=f"Threat analyzed by {output['detection']['model_name']} and resolved in {output['resolution']['mode']} mode.",
                metrics=metrics,
                history_html=_history_table(self.history),
            )
        )


def main() -> None:
    server = HTTPServer(("0.0.0.0", 8501), Handler)
    print("AI SOC Copilot running at http://0.0.0.0:8501")
    server.serve_forever()


if __name__ == "__main__":
    main()
