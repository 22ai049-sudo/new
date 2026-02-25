# AI SOC Copilot (Python)

A functional multi-file Python SOC project with a dashboard that can:

- Automatically detect threat likelihood using an ML-style detection engine
- Analyze incidents using LLM-style reasoning and MITRE ATT&CK mapping
- Enrich decisions with RAG-style evidence snippets
- Validate safety using ATAVE-style policy and risk checks
- Auto-resolve incidents with generated playbook steps
- Simulate execution in a sandbox and show explainable JSON output

## Project Structure

- `app.py` - Built-in Python HTTP dashboard UI
- `cli_demo.py` - CLI run for quick testing
- `soc_ai/models.py` - Core dataclasses
- `soc_ai/engines.py` - Detection, reasoning, resolver, validation, sandbox pipeline
- `soc_ai/knowledge.py` - MITRE and policy knowledge base
- `tests/test_pipeline.py` - Functional test

## Run

```bash
python3 cli_demo.py
python3 app.py
```

Open: `http://localhost:8501`

## Test

```bash
pytest -q
```
