"""
cli.py — Command-line interface for ghost-data-audit.

Commands:
  validate   Validate CSV inputs and evidence manifest; report errors.
  run        Run the audit on deletion_requests.csv and write output.csv.
  evaluate   Compare output.csv against a gold file (default: sample_output.csv).
  test       Run pytest on the tests/ directory.
  package    Create code.zip for submission.

Usage:
  python -m ghost_audit.cli validate [--config CONFIG]
  python -m ghost_audit.cli run [--config CONFIG] [--sample] [--limit N] [--llm-mode MODE]
  python -m ghost_audit.cli evaluate [--predicted PATH] [--gold PATH]
  python -m ghost_audit.cli evaluate-harness [--config CONFIG]
  python -m ghost_audit.cli test
  python -m ghost_audit.cli package [--out PATH]
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import os
import subprocess
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Lazy imports for commands to keep startup fast
logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        level=level,
    )


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def cmd_validate(args: argparse.Namespace) -> int:
    """Validate all CSV inputs and evidence manifest."""
    from .config import load_config
    from .input_loader import (
        load_deletion_requests,
        load_deletion_rules,
        load_evidence_manifest,
        load_system_activity,
        load_user_audit_log,
        load_user_identities,
    )

    cfg = load_config(Path(args.config) if args.config else None)
    errors: List[str] = []

    checks = [
        ("deletion_requests", cfg.dataset.deletion_requests, load_deletion_requests),
        ("sample_requests", cfg.dataset.sample_requests, load_deletion_requests),
        ("user_identities", cfg.dataset.user_identities, load_user_identities),
        ("user_audit_log", cfg.dataset.user_audit_log, load_user_audit_log),
        ("deletion_rules", cfg.dataset.deletion_rules, load_deletion_rules),
        ("evidence_manifest", cfg.dataset.evidence_files, load_evidence_manifest),
    ]

    for name, path, loader in checks:
        if not path.exists():
            errors.append(f"MISSING: {name} at {path}")
            continue
        try:
            result = loader(path)
            n = len(result) if hasattr(result, "__len__") else len(list(result.values()))
            print(f"  OK  {name}: {n} rows — {path}")
        except Exception as exc:
            errors.append(f"ERROR  {name}: {exc}")

    # Check evidence directory
    ev_dir = cfg.dataset.evidence_dir
    if not ev_dir.exists():
        errors.append(f"MISSING: evidence directory at {ev_dir}")
    else:
        ev_files = list(ev_dir.rglob("*"))
        non_dir = [f for f in ev_files if f.is_file()]
        print(f"  OK  evidence directory: {len(non_dir)} files")

    try:
        requests = load_deletion_requests(cfg.dataset.deletion_requests)
        request_ids = [case.case_id for case in requests]
        print(f"  OK  evaluation requests: {len(request_ids)} rows, {len(set(request_ids))} unique case_ids")
        print(f"       first5={sorted(request_ids, key=lambda x: int(x.split('_')[-1]))[:5]}")
        print(f"       last5={sorted(request_ids, key=lambda x: int(x.split('_')[-1]))[-5:]}")
        if len(request_ids) != 518:
            errors.append(f"EXPECTED 518 requests, discovered {len(request_ids)}")
    except Exception as exc:
        errors.append(f"ERROR evaluation requests: {exc}")
    try:
        refs = load_evidence_manifest(cfg.dataset.evidence_files)
        missing = [ref.file_id for ref in refs if not (cfg.dataset.root / ref.file_path).exists()]
        duplicates = len(refs) - len({ref.file_id for ref in refs})
        if missing or duplicates:
            errors.append(f"Evidence manifest entries invalid: missing={missing[:10]} duplicates={duplicates}")
        print(f"  OK  evidence manifest files present: {len(refs) - len(missing)}/{len(refs)}")
    except Exception as exc:
        errors.append(f"ERROR evidence manifest entries: {exc}")

    if errors:
        print("\nValidation FAILED:")
        for e in errors:
            print(f"  {e}")
        return 1
    print("\nAll checks passed.")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    """Run deterministic evidence ingestion and write a PII-free coverage report."""
    import json
    from collections import Counter
    from .config import load_config
    from .evidence_ingestion.manifest import ManifestIndex
    from .evidence_ingestion.pipeline import EvidenceIngestionPipeline
    from .input_loader import load_evidence_manifest, load_user_audit_log, load_user_identities

    cfg = load_config(Path(args.config) if getattr(args, "config", None) else None)
    refs = load_evidence_manifest(cfg.dataset.evidence_files)
    identities = load_user_identities(cfg.dataset.user_identities)
    audit_rows = load_user_audit_log(cfg.dataset.user_audit_log)
    identifiers = {
        value.strip().lower()
        for row in identities.values()
        for value in row.values()
        if isinstance(value, str) and value.strip()
    }
    for row in audit_rows:
        for field in ("old_value", "new_value", "user_id"):
            value = row.get(field, "").strip().lower()
            if value:
                identifiers.add(value)

    # Manifest paths are relative to dataset/ (they include the evidence/ prefix).
    manifest = ManifestIndex(cfg.dataset.evidence_files, cfg.dataset.root)
    pipeline = EvidenceIngestionPipeline(manifest, cfg.dataset.root)
    facts = pipeline.read_all(refs, identifiers)
    facts_by_file = Counter(f.file_id for f in facts)
    summary = pipeline.gap_tracker.summary()
    gap_ids = set(summary["gap_file_ids"])
    missing_ids = {ref.file_id for ref in refs if not (cfg.dataset.root / ref.file_path).exists()}
    entries = []
    for ref in sorted(refs, key=lambda item: item.file_id):
        if ref.file_id in missing_ids:
            state = "missing"
        elif facts_by_file[ref.file_id]:
            state = "parsed_with_facts"
        elif ref.file_id in gap_ids:
            state = "parsed_no_matching_facts"
        else:
            state = "parsed_no_facts_or_unclassified"
        entries.append({
            "file_id": ref.file_id,
            "format": ref.format.value,
            "exists": ref.file_id not in missing_ids,
            "coverage_state": state,
            "fact_count": facts_by_file[ref.file_id],
        })
    report = {
        "manifest_entries": len(refs),
        "facts_extracted": len(facts),
        "warnings": summary["warnings"],
        "gaps": summary["gaps"],
        "missing_files": sorted(missing_ids),
        "entries": entries,
        "privacy_note": "No evidence text, identifiers, or raw values are written here.",
    }
    destination = cfg.output.evaluation_dir / "evidence_coverage.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("manifest_entries", "facts_extracted", "warnings", "gaps", "missing_files")}, indent=2))
    print(f"Coverage report written to {destination}")
    return 1 if missing_ids else 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    """Run the full audit pipeline."""
    from .audit_engine import AuditEngine
    from .config import load_config
    from .input_loader import (
        load_deletion_requests,
        load_deletion_rules,
        load_evidence_manifest,
        load_system_activity,
        load_user_audit_log,
        load_user_identities,
    )
    from .output_writer import numeric_case_key, validate_output, write_output

    cfg = load_config(Path(args.config) if args.config else None)
    if args.sample:
        cfg.sample_only = True
    if args.limit:
        cfg.case_limit = int(args.limit)
    if args.llm_mode:
        cfg.llm.mode = args.llm_mode

    start_time = datetime.now(timezone.utc)
    event_counts = {"warnings": 0, "errors": 0}

    class _EventCounter(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if record.levelno >= logging.ERROR:
                event_counts["errors"] += 1
            elif record.levelno >= logging.WARNING:
                event_counts["warnings"] += 1

    _setup_logging(cfg.verbose or args.verbose)
    event_handler = _EventCounter()
    logging.getLogger().addHandler(event_handler)
    logger.info("Loading dataset...")

    identities = load_user_identities(cfg.dataset.user_identities)
    audit_log = load_user_audit_log(cfg.dataset.user_audit_log)
    rules = load_deletion_rules(cfg.dataset.deletion_rules)
    manifest = load_evidence_manifest(cfg.dataset.evidence_files)
    activity = load_system_activity(cfg.dataset.system_activity)

    requests_path = (
        cfg.dataset.sample_requests if cfg.sample_only
        else cfg.dataset.deletion_requests
    )
    cases = load_deletion_requests(requests_path)
    if cfg.case_limit:
        cases = cases[: cfg.case_limit]

    # Gate 1: exact request population and canonical IDs.  The loader sorts;
    # this preflight reads the raw IDs to detect duplicates before any run.
    with requests_path.open(newline="", encoding="utf-8") as handle:
        raw_request_rows = list(csv.DictReader(handle))
    raw_ids = [row.get("case_id", "") for row in raw_request_rows]
    duplicate_ids = sorted([cid for cid, count in Counter(raw_ids).items() if count > 1])
    if not cfg.sample_only and len(raw_ids) != 518:
        raise RuntimeError(f"Request-count gate failed: discovered {len(raw_ids)} requests, expected 518")
    if duplicate_ids:
        raise RuntimeError(f"Request-ID gate failed: duplicate case_ids {duplicate_ids[:10]}")
    if len(set(raw_ids)) != len(raw_ids):
        raise RuntimeError("Request-ID gate failed: non-unique case IDs")
    canonical_ids = sorted(raw_ids, key=numeric_case_key)
    print(f"Discovered requests={len(raw_ids)} unique_case_ids={len(set(raw_ids))}")
    print(f"Input first5={canonical_ids[:5]}")
    print(f"Input last5={canonical_ids[-5:]}")

    # Gate 2: supplied sample reference must parse before running cases.
    sample_cases = load_deletion_requests(cfg.dataset.sample_requests)
    sample_reference_errors = validate_output(
        cfg.dataset.sample_output,
        [case.case_id for case in sample_cases],
    )
    if sample_reference_errors:
        raise RuntimeError("Sample-reference schema gate failed: " + "; ".join(sample_reference_errors[:10]))
    missing_manifest_files = [
        ref.file_id for ref in manifest if not (cfg.dataset.root / ref.file_path).exists()
    ]
    manifest_ids = [ref.file_id for ref in manifest]
    if missing_manifest_files or len(manifest_ids) != len(set(manifest_ids)):
        raise RuntimeError(
            f"Evidence manifest gate failed: missing_files={missing_manifest_files[:10]} duplicate_ids={len(manifest_ids) - len(set(manifest_ids))}"
        )

    logger.info("Processing %d cases...", len(cases))
    engine = AuditEngine(
        config=cfg,
        identities=identities,
        audit_log=audit_log,
        deletion_rules=rules,
        evidence_manifest=manifest,
        dataset_root=cfg.dataset.root,
        activity_rows=activity,
    )
    engine.usage.total_cases = len(cases)

    results = []
    run_errors = 0
    for i, case in enumerate(cases):
        try:
            result = engine.audit_case(case)
            results.append(result)
            if cfg.verbose or (i % 50 == 0 and i > 0):
                logger.info("Progress: %d/%d", i + 1, len(cases))
        except Exception as exc:
            run_errors += 1
            logger.error("Error on %s: %s", case.case_id, exc)
            from .schemas import CaseResult, DeletionStatus
            results.append(CaseResult(
                case_id=case.case_id,
                deletion_status=DeletionStatus.INCOMPLETE,
                error=str(exc),
            ))

    allowed_evidence_ids = set(manifest_ids)
    allowed_evidence_ids.update(row.get("activity_id", "") for row in activity if row.get("activity_id"))
    allowed_evidence_ids.update(row.get("audit_id", "") for row in load_user_audit_log(cfg.dataset.user_audit_log) if row.get("audit_id"))
    write_output(
        results,
        cfg.output.output_csv,
        expected_case_ids=canonical_ids,
        allowed_evidence_ids=allowed_evidence_ids,
    )
    serialized_errors = validate_output(
        cfg.output.output_csv,
        canonical_ids,
        allowed_evidence_ids=allowed_evidence_ids,
    )
    if serialized_errors:
        raise RuntimeError("Serialized output gate failed: " + "; ".join(serialized_errors[:20]))
    with cfg.output.output_csv.open(newline="", encoding="utf-8") as handle:
        exported_ids = [row["case_id"] for row in csv.DictReader(handle)]
    print(f"Output first5={exported_ids[:5]}")
    print(f"Output last5={exported_ids[-5:]}")
    print(f"Output set differences missing={sorted(set(canonical_ids) - set(exported_ids))} extra={sorted(set(exported_ids) - set(canonical_ids))}")
    logger.info("Done. Usage: %s LLM calls, %s total tokens",
                engine.usage.llm_calls, engine.usage.total_tokens)

    # Write manifest
    import json
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    dataset_hashes = {}
    for dataset_path in sorted(cfg.dataset.root.rglob("*")):
        if dataset_path.is_file():
            dataset_hashes[str(dataset_path.relative_to(cfg.dataset.root))] = _sha256(dataset_path)
    try:
        source_revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=cfg.dataset.root.parent, text=True,
        ).strip()
    except Exception:
        source_revision = None
    status_counts = Counter(result.deletion_status.value for result in results)
    end_time = datetime.now(timezone.utc)
    manifest_data = {
        "started_at": start_time.isoformat(),
        "ended_at": end_time.isoformat(),
        "invocation": " ".join([sys.executable] + sys.argv),
        "source_revision": source_revision,
        "dataset_input_sha256": dataset_hashes,
        "config_redacted": cfg.model_dump(mode="json"),
        "cases_processed": len(results),
        "request_count": len(raw_ids),
        "unique_case_ids": len(set(raw_ids)),
        "row_count": len(exported_ids),
        "status_counts": dict(status_counts),
        "warnings_count": event_counts["warnings"],
        "errors_count": event_counts["errors"] + run_errors,
        "llm_calls": engine.usage.llm_calls,
        "total_tokens": engine.usage.total_tokens,
        "measured_calls": engine.usage.measured_calls,
        "unknown_token_calls": engine.usage.unknown_token_calls,
        "cache_hits": engine.usage.cache_hits,
        "cache_misses": engine.usage.cache_misses,
        "retries": engine.usage.retries,
        "failures": engine.usage.failures,
        "call_records": engine.usage.call_records,
        "provider": "ollama-local" if cfg.llm.provider == "ollama" else cfg.llm.provider,
        "model": engine.usage.model_name or cfg.llm.ollama_model,
        "output_path": str(cfg.output.output_csv),
        "output_sha256": _sha256(cfg.output.output_csv),
        "report_paths": {
            "evaluation_report": str(cfg.output.evaluation_dir / "evaluation_report.md"),
            "usage_report": str(cfg.output.evaluation_dir / "usage_report.md"),
        },
    }
    cfg.output.manifest_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.output.manifest_path.write_text(json.dumps(manifest_data, indent=2))
    usage = engine.usage
    cfg.output.evaluation_dir.mkdir(parents=True, exist_ok=True)
    (cfg.output.evaluation_dir / "usage_report.md").write_text(
        "# Usage report\n\n"
        f"- Cases: {len(cases)} (full benchmark target: 518)\n"
        f"- Provider: {manifest_data['provider']}\n"
        f"- Model: {manifest_data['model']}\n"
        f"- Actual model calls (including retries/failures): {usage.llm_calls}\n"
        f"- Cache hits / misses: {usage.cache_hits} / {usage.cache_misses}\n"
        f"- Retries / failures: {usage.retries} / {usage.failures}\n"
        f"- Measured input tokens: {usage.input_tokens}\n"
        f"- Measured output tokens: {usage.output_tokens}\n"
        f"- Measured total tokens: {usage.total_tokens}\n"
        f"- Calls with unknown token counts: {usage.unknown_token_calls}\n"
        f"- Mean measured tokens per request: {usage.total_tokens / len(cases) if cases else 0:.2f}\n"
        "- Estimated provider/API cost: $0.00 (local Ollama; electricity and hardware excluded)\n"
        "\nToken counts are reported only when Ollama returned prompt/evaluation counts.\n",
        encoding="utf-8",
    )
    cfg.output.log_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.output.log_path.write_text(
        "\n".join([
            f"{start_time.isoformat()} FINAL_RUN_START cases={len(cases)} mode={cfg.llm.mode} provider=ollama-local model={manifest_data['model']}",
            f"{end_time.isoformat()} OUTPUT_VALIDATED rows={len(exported_ids)} warnings={manifest_data['warnings_count']} errors={manifest_data['errors_count']}",
            f"{end_time.isoformat()} FINAL_RUN_END output_sha256={manifest_data['output_sha256']}",
        ]) + "\n",
        encoding="utf-8",
    )
    cfg.output.manifest_path.write_text(json.dumps(manifest_data, indent=2, ensure_ascii=False), encoding="utf-8")
    logging.getLogger().removeHandler(event_handler)
    return 0


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------

def cmd_evaluate(args: argparse.Namespace) -> int:
    """Evaluate predicted output.csv against a gold file."""
    from .config import load_config
    from .evaluator import evaluate

    cfg = load_config(Path(args.config) if getattr(args, "config", None) else None)
    predicted = Path(args.predicted) if args.predicted else cfg.output.output_csv
    gold = Path(args.gold) if args.gold else cfg.dataset.sample_output

    report = evaluate(predicted, gold)
    md = report.to_markdown()
    print(md)

    # Write to evaluation/evaluation_report.md
    eval_dir = cfg.output.evaluation_dir
    eval_dir.mkdir(parents=True, exist_ok=True)
    report_path = eval_dir / "evaluation_report.md"
    report_path.write_text(md, encoding="utf-8")
    print(f"\nReport written to {report_path}")
    return 0 if report.errors == [] else 1


def cmd_evaluate_harness(args: argparse.Namespace) -> int:
    """Generate raw sample/custom/adversarial metrics and Markdown report."""
    import importlib.util
    harness_path = Path(__file__).resolve().parents[2] / "evaluation" / "harness.py"
    spec = importlib.util.spec_from_file_location("ghost_audit_evaluation_harness", harness_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load evaluation harness: {harness_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run_harness(Path(args.config) if args.config else None)
    print(f"Evaluation artifacts written to {harness_path.parent}")
    return 0


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

def cmd_test(args: argparse.Namespace) -> int:
    """Run pytest on the tests/ directory."""
    # Locate tests directory relative to the package
    pkg_dir = Path(__file__).parent
    project_root = pkg_dir.parent.parent  # src/ghost_audit -> src -> ghost-data-audit
    tests_dir = project_root / "tests"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(tests_dir), "-v"],
        check=False,
    )
    return result.returncode


# ---------------------------------------------------------------------------
# package
# ---------------------------------------------------------------------------

def cmd_package(args: argparse.Namespace) -> int:
    """Create code.zip from the explicit submission allowlist."""
    from .config import load_config
    cfg = load_config(None)
    repo_root = Path(__file__).resolve().parents[4]
    project_root = repo_root / "code" / "ghost-data-audit"
    out_path = Path(args.out) if getattr(args, "out", None) else repo_root / "code.zip"

    required = [
        repo_root / "README.md",
        repo_root / "AI_USE_DISCLOSURE.md",
        repo_root / "chat_transcript.md",
        repo_root / "docs" / "contracts.md",
        repo_root / "docs" / "gap_analysis.md",
        repo_root / "output.csv",
        project_root / "README.md",
        project_root / "config.example.yaml",
        project_root / "requirements.txt",
        project_root / "prompts",
        project_root / "src",
        project_root / "tests",
        project_root / "evaluation" / "harness.py",
        project_root / "evaluation" / "custom_cases.json",
        project_root / "evaluation" / "sample_metrics.json",
        project_root / "evaluation" / "custom_metrics.json",
        project_root / "evaluation" / "adversarial_results.json",
        project_root / "evaluation" / "evidence_coverage.json",
        project_root / "evaluation" / "evaluation_report.md",
        project_root / "evaluation" / "usage_report.md",
        project_root / "logs" / "final_run.log",
        project_root / "logs" / "final_run_manifest.json",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise RuntimeError("Cannot package; required final artifacts are missing: " + ", ".join(missing))

    allow_files = set()
    for path in required:
        if path.is_file():
            allow_files.add(path)
        elif path.is_dir():
            allow_files.update(p for p in path.rglob("*") if p.is_file())
    allow_files.update(p for p in (repo_root / "code").glob("*.py") if p.is_file())
    allow_files.update(p for p in (repo_root / "code" / "tests").rglob("*.py") if p.is_file())

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(allow_files):
            if file == out_path or file.suffix in {".pyc", ".pyo"}:
                continue
            if any(part in {"__pycache__", ".pytest_cache", ".cache", ".venv", "venv"} for part in file.parts):
                continue
            zf.write(file, file.relative_to(repo_root))

    print(f"Created {out_path} ({out_path.stat().st_size / 1024:.1f} KB)")
    return 0


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ghost_audit",
        description="Ghost Data Still Exists — deletion audit agent",
    )
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    # validate
    p_val = sub.add_parser("validate", help="Validate dataset inputs")
    p_val.add_argument("--config", default=None, help="Path to config.yaml")

    # coverage
    p_cov = sub.add_parser("coverage", help="Generate deterministic evidence coverage report")
    p_cov.add_argument("--config", default=None)

    # run
    p_run = sub.add_parser("run", help="Run audit on deletion requests")
    p_run.add_argument("--config", default=None)
    p_run.add_argument("--sample", action="store_true", help="Use sample_deletion_requests.csv")
    p_run.add_argument("--limit", type=int, default=None, help="Process only first N cases")
    p_run.add_argument("--llm-mode", choices=["off", "auto", "on"], default=None)
    p_run.add_argument("--verbose", action="store_true")

    # evaluate
    p_eval = sub.add_parser("evaluate", help="Score output.csv against gold")
    p_eval.add_argument("--predicted", default=None, help="Predicted output.csv path")
    p_eval.add_argument("--gold", default=None, help="Gold output.csv path")
    p_eval.add_argument("--config", default=None)

    p_harness = sub.add_parser("evaluate-harness", help="Generate reproducible evaluation artifacts")
    p_harness.add_argument("--config", default=None)

    # test
    sub.add_parser("test", help="Run unit tests")

    # package
    p_pkg = sub.add_parser("package", help="Create code.zip")
    p_pkg.add_argument("--out", default=None, help="Output zip path")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    dispatch = {
        "validate": cmd_validate,
        "coverage": cmd_coverage,
        "run": cmd_run,
        "evaluate": cmd_evaluate,
        "evaluate-harness": cmd_evaluate_harness,
        "test": cmd_test,
        "package": cmd_package,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
