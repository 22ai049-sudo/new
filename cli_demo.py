from __future__ import annotations

import json

from soc_ai.engines import SOCPipeline


def main() -> None:
    pipeline = SOCPipeline()
    output = pipeline.run(
        {
            "source": "siem",
            "severity": "high",
            "event": "Suspicious mail phishing campaign detected with credential lure",
            "src_ip": "185.11.22.9",
            "dst_asset": "employee-mailbox-42",
        },
        auto_resolve=True,
    )
    print(json.dumps(output.as_dict(), indent=2))


if __name__ == "__main__":
    main()
