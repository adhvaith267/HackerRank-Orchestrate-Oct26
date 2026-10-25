# Ghost Data Still Exists — Deletion Audit Agent

AI-powered audit agent for the HackerRank Orchestrate challenge.

For each deletion request, the agent determines whether deletion was authorized,
resolves the subject's current and historical identifiers, searches all evidence
for ghost data, applies the deletion policy, and produces an ordered
finding + remediation + verification plan.

## Complete submission guide

This README is the canonical guide for running and submitting the solution.

Contents: [purpose](#purpose) · [architecture](#architecture) ·
[installation](#requirements-and-installation) · [commands](#commands) ·
[inputs](#inputs) · [output contract](#output-contract) · [LLM](#optional-local-ollama)
· [testing](#testing-and-verification) · [limitations](#limitations-and-security)

## Purpose

This is an audit and planning tool for distributed-data deletion requests. It
does not delete real data or call production systems. For each request it
determines whether deletion is authorized, resolves current and historical
aliases to a stable user, reconstructs resource state at `audit_at`, applies
the supplied retention rules, checks synchronization/import activity and
backup/restore risk, and emits a validated `output.csv` row.

The pipeline is:

```text
CSV requests/evidence -> input validation -> identity resolution
-> SQL/JSON/log/TXT/PDF/image ingestion -> temporal reconstruction
-> policy + flow + restore analysis -> status and step planning
-> validated atomic output.csv
```

Important safety properties:

- Evidence captured after `audit_at` cannot prove an earlier state.
- Unknown, contradictory, malformed, or insufficient evidence is handled
  conservatively as `INCOMPLETE`.
- Optional LLM output is candidate evidence only; it cannot choose status,
  policy, identifiers, remediation, or final steps.
- Final steps are generated from typed `AuditAnalysis` and validated before
  the output is written.

The default repository-level inputs are `dataset/deletion_requests.csv`,
`user_identities.csv`, `user_audit_log.csv`, `system_activity.csv`,
`deletion_rules.csv`, `evidence_files.csv`, and `dataset/evidence/`. The
default output is repository-level `output.csv`.

Key package areas are `schemas.py` (typed models), `input_loader.py` (CSV
loading), `identity.py` (alias resolution), `temporal.py` (time-aware state),
`policy.py` (rules), `evidence_ingestion/` (SQL/JSON/log/text/PDF/image
readers), `audit_core.py` and `audit_engine.py` (analysis), `step_builder.py`
(ordered plans), `output_writer.py` (validation), and `evaluator.py` (metrics).

## Requirements and installation

- Python 3.10+; Python 3.12 is recommended.
- Packages in `requirements.txt`.
- `poppler-utils` / `pdftotext` for PDF extraction:

```bash
sudo apt-get install -y poppler-utils
python3 -m venv .venv
. .venv/bin/activate
pip install -r code/ghost-data-audit/requirements.txt
export PYTHONPATH="$PWD/code/ghost-data-audit/src"
```

Ollama is optional. No hosted model, API key, or external service is required.

## Commands

Run from the repository root after setting `PYTHONPATH`:

```bash
python3 -m ghost_audit.cli validate
python3 -m ghost_audit.cli run --llm-mode off
python3 -m ghost_audit.cli run --sample
python3 -m ghost_audit.cli run --limit 10
python3 -m ghost_audit.cli run --llm-mode auto
python3 -m ghost_audit.cli evaluate --predicted output.csv --gold dataset/sample_output.csv
python3 -m ghost_audit.cli evaluate-harness
pytest -q code/ghost-data-audit/tests code/tests
```

The package also supports `PYTHONPATH=src python3 -m ghost_audit.cli test`
from this directory. Create an archive from the repository root with:

```bash
python3 -m ghost_audit.cli package --out code.zip
```

## Output contract

The output header is exactly:

```csv
case_id,deletion_status,steps_json
```

Steps use `FINDING`, `REMEDIATION`, and `VERIFICATION` phases. `COMPLETE`
rows contain verification steps backed by real evidence. `INCOMPLETE` rows
contain evidence-backed findings followed by proposed remediation and future
verification steps. `NOT_APPLICABLE` rows contain `[]`. The writer validates
headers, enums, operation/state pairs, evidence IDs, ordering, and consecutive
step numbers before replacing the output.

## Optional local Ollama

```bash
ollama serve
ollama pull qwen2.5:7b
python3 -m ghost_audit.cli run --llm-mode auto
```

`off` is deterministic-only, `auto` calls Ollama for eligible ambiguity, and
`on` calls it for all eligible unstructured evidence. Responses are bounded,
schema-validated, and checked against source IDs and quotes. Missing Ollama,
timeouts, retries, malformed output, and low-quality extraction fall back to
deterministic handling and explicit gaps. Configuration is in
`config.example.yaml`.

## Limitations and security

- This tool plans and verifies deletion; it does not execute deletion.
- Results are limited to supplied evidence and metadata discoverable by the
  dataset. Evidence after `audit_at` is intentionally excluded.
- Activity logs may indicate recreation or synchronization but are not alone
  proof of final resource state.
- Missing, unreadable, contradictory, or ungrounded evidence prevents a
  `COMPLETE` result rather than causing an invented resource or step.
- PDF extraction depends on `pdftotext`; image/OCR depends on local tooling
  and, when enabled, local model availability.
- Sample/reference metrics do not guarantee hidden-test accuracy; the data is
  synthetic and is not production compliance validation.
- The default workflow is local-only: evidence is not uploaded and no hosted
  API is called. Review local logs and caches before sharing them.

## Extended command reference

---

## Setup

### Prerequisites

- Python 3.10+
- `poppler-utils` (for PDF extraction): `sudo apt-get install -y poppler-utils`
- Optional: Ollama running locally for evidence normalization (`http://localhost:11434`)

### Install

```bash
cd code/ghost-data-audit
pip install -r requirements.txt
```

### Configure

```bash
cp config.example.yaml config.yaml
# Edit config.yaml if your dataset path differs from the default.
# All paths default to <repo_root>/dataset/ automatically.
# Ollama runs locally and requires no API key.
```

---

## Commands

All commands are run from `code/ghost-data-audit/`.

### Validate inputs

Checks that all required CSV files and evidence directories exist and are parseable.

```bash
python -m ghost_audit.cli validate
```

### Run the audit

Process all 518 cases and write `output.csv` to the repository root.

```bash
python -m ghost_audit.cli run
```

Optional flags:
```bash
python -m ghost_audit.cli run --sample          # Use sample_deletion_requests.csv (32 cases)
python -m ghost_audit.cli run --limit 10        # First 10 cases only
python -m ghost_audit.cli run --llm-mode off    # Disable LLM (deterministic only)
python -m ghost_audit.cli run --llm-mode auto   # local Ollama for ambiguous evidence
python -m ghost_audit.cli run --llm-mode on     # Always call LLM
python -m ghost_audit.cli run --verbose         # Debug logging
```

### Evaluate

Compare the generated `output.csv` against the sample gold answers.

```bash
python -m ghost_audit.cli evaluate
# Or specify paths explicitly:
python -m ghost_audit.cli evaluate \
  --predicted ../../output.csv \
  --gold ../../dataset/sample_output.csv

# Generate reproducible sample/custom/adversarial metrics and reports
python -m ghost_audit.cli evaluate-harness
```

Writes a report to `evaluation/evaluation_report.md`.

### Run tests

```bash
python -m ghost_audit.cli test
# Or directly:
python -m pytest tests/ -v
```

### Package for submission

Creates `code.zip` (excludes dataset, venv, caches, credentials).

```bash
python -m ghost_audit.cli package
# Or specify output path:
python -m ghost_audit.cli package --out ../../code.zip
```

---

## Architecture

```
src/ghost_audit/
├── schemas.py       — All typed data models and validation
├── config.py        — YAML-based configuration loader
├── input_loader.py  — CSV loaders for all dataset files
├── identity.py      — Email → user_id + historical alias resolution
├── temporal.py      — Resource state reconstruction at audit_at
├── policy.py        — Deletion policy rule evaluation
├── evidence.py      — Evidence file loading (SQL, JSON, LOG, PDF, IMAGE, TXT)
├── data_flows.py    — DataFlowState and RestoreRisk extraction
├── llm.py           — LLM client (Ollama, OpenAI) for classification + OCR
├── step_builder.py  — Ordered AuditStep assembly
├── audit_engine.py  — Top-level per-case orchestration
├── output_writer.py — output.csv writer and validator
├── evaluator.py     — Comparison against gold answers
└── cli.py           — CLI entry point
```

### Processing pipeline per case

1. **Classify** `request_text` → authorized deletion or NOT_APPLICABLE
2. **Resolve identity** → `user_id` + all current and historical emails/hashes/phones
3. **Filter evidence** → only files with `captured_at <= audit_at`
4. **Extract facts** from all eligible evidence files (SQL, JSON, logs, PDFs, images)
5. **Reconstruct state** at `audit_at` per resource (most recent eligible evidence)
6. **Evaluate policy** → `AuditFinding` list (violations + data flow/restore risks)
7. **Determine status** → COMPLETE (no findings) or INCOMPLETE (has findings)
8. **Build steps** → ordered FINDING + REMEDIATION + VERIFICATION steps
9. **Write output row** → `case_id, deletion_status, steps_json`

---

## LLM configuration

| Mode | Behavior |
|---|---|
| `off` | No LLM calls. Rule-based classification only. Fast and deterministic. |
| `auto` | LLM called only for ambiguous `request_text` and image evidence. |
| `on` | LLM called for every request classification and every image file. |

Only local Ollama is supported. Hosted model APIs are intentionally disabled.
The reproducible final benchmark default is `llm.mode: off`; the latest measured
full run used `auto` after local memory testing. The starting model is `qwen2.5:7b`; an
explicit `qwen3:8b` override is available through `OLLAMA_MODEL` or
`ollama_model_override`. Evidence is never uploaded.

Usage accounting records every local call, retry, failure, cache hit, and
measured token count. Local inference has $0 provider/API charge; electricity
and hardware costs are excluded. Missing Ollama or malformed output falls back
to deterministic parsing and explicit unknowns.

---

## Output format

`output.csv` — 518 rows + header:

```csv
case_id,deletion_status,steps_json
case_33,COMPLETE,"[{""step_no"":1,""phase"":""VERIFICATION"",...}]"
```

`deletion_status`: `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`
`steps_json`: compact JSON array, keys alphabetical within each object

---

## Submission artifacts

| Item | Path |
|---|---|
| Runnable solution | `code/ghost-data-audit/` |
| Output CSV | `output.csv` (repo root) |
| Evaluation report | `code/ghost-data-audit/evaluation/evaluation_report.md` |
| Usage report | `code/ghost-data-audit/evaluation/usage_report.md` |
| Prompts | `code/ghost-data-audit/prompts/evidence_extraction.md` |
| Chat transcript | `log.txt` (repo root) |
