from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from typing import Any


class SandboxExecutor:
    """Runs validated commands inside ephemeral Docker containers."""

    def execute(self, commands: list[str], image: str = "alpine:3.20") -> dict[str, Any]:
        logs: list[dict[str, Any]] = []
        for command in commands:
            docker_cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                image,
                "sh",
                "-lc",
                command,
            ]
            try:
                result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=30, check=False)
                logs.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "command": command,
                        "exit_code": result.returncode,
                        "stdout": result.stdout.strip(),
                        "stderr": result.stderr.strip(),
                        "sandbox_isolation": "docker_ephemeral_no_network_capdrop_all",
                    }
                )
            except FileNotFoundError:
                logs.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "command": command,
                        "exit_code": -1,
                        "stdout": "",
                        "stderr": "Docker runtime not found on host",
                        "sandbox_isolation": "docker_unavailable",
                    }
                )
            except subprocess.TimeoutExpired:
                logs.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "command": command,
                        "exit_code": -2,
                        "stdout": "",
                        "stderr": "Command timed out in sandbox",
                        "sandbox_isolation": "docker_ephemeral_no_network_capdrop_all",
                    }
                )

        return {
            "executed_commands": len(commands),
            "sandbox_logs": logs,
        }
