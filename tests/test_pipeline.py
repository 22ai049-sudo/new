from soc_ai.engines import SOCPipeline


def test_pipeline_output_structure() -> None:
    pipeline = SOCPipeline()
    output = pipeline.run(
        {
            "source": "suricata",
            "severity": "high",
            "event": "credential brute force detected",
            "src_ip": "10.0.0.1",
        },
        auto_resolve=True,
    )

    data = output.as_dict()
    assert "alert" in data
    assert "detection" in data
    assert "reasoning" in data
    assert "resolution" in data
    assert "validation" in data
    assert "sandbox" in data
    assert data["detection"]["threat_detected"] is True
    assert data["validation"]["verdict"] in {"Approve", "Reject", "Modify", "Require Human Review"}
    assert data["resolution"]["mode"] == "auto"
