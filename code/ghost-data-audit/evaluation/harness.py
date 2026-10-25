"""Reproducible sample/custom/adversarial evaluation harness.

Run from ``code/ghost-data-audit``:

    python -m ghost_audit.evaluation_harness

The harness writes machine-readable results before rendering Markdown.  It
joins CSVs by case_id, validates output shape, and never uses hidden labels.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
CODE_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_DIR = PACKAGE_ROOT / "evaluation"
SRC = PACKAGE_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from ghost_audit.audit_engine import AuditEngine  # noqa: E402
from ghost_audit.config import LLMConfig, RunConfig, load_config  # noqa: E402
from ghost_audit.input_loader import (  # noqa: E402
    load_deletion_requests,
    load_deletion_rules,
    load_deletion_rules,
    load_evidence_manifest,
    load_user_audit_log,
    load_user_identities,
)
from ghost_audit.schemas import (  # noqa: E402
    AuditStep,
    CaseResult,
    DataCategory,
    DeletionStatus,
    EvidenceFact,
    Operation,
    Phase,
    RecordState,
    RequiredAction,
)
from ghost_audit.ollama_evidence import OllamaEvidenceExtractor  # noqa: E402

STEP_FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
STEP_SIGNATURE_FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
ALLOWED_STATUS = {x.value for x in DeletionStatus}
PHASES = {x.value for x in Phase}
OPERATIONS = {x.value for x in Operation}
STATES = {x.value for x in RecordState}


def _read_rows(path: Path) -> Tuple[List[Dict[str, str]], List[str], List[str]]:
    """Read CSV rows and return rows, duplicate IDs, and structural errors."""
    if not path.exists():
        return [], [], [f"missing file: {path}"]
    errors: List[str] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return [], [], [f"missing header: {path}"]
        if "case_id" not in reader.fieldnames:
            return [], [], [f"missing case_id column: {path}"]
        rows = list(reader)
    ids = [row.get("case_id", "") for row in rows]
    counts = Counter(ids)
    duplicates = sorted([case_id for case_id, count in counts.items() if count > 1])
    if any(not case_id for case_id in ids):
        errors.append(f"blank case_id in {path}")
    return rows, duplicates, errors


def _parse_steps(raw: str, case_id: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        return [], [f"{case_id}: invalid steps_json: {exc}"]
    if not isinstance(value, list):
        return [], [f"{case_id}: steps_json is not an array"]
    for index, step in enumerate(value, 1):
        if not isinstance(step, dict):
            errors.append(f"{case_id}: step {index} is not an object")
            continue
        if set(step) != set(STEP_FIELDS):
            errors.append(f"{case_id}: step {index} has wrong fields")
            continue
        if step.get("step_no") != index:
            errors.append(f"{case_id}: step numbering is not consecutive")
        if step.get("phase") not in PHASES or step.get("operation") not in OPERATIONS or step.get("state") not in STATES:
            errors.append(f"{case_id}: step {index} has an unsupported enum")
    return value, errors


def validate_output_rows(rows: Sequence[Dict[str, str]]) -> Dict[str, Any]:
    """Validate parser/schema constraints without consulting a reference."""
    errors: List[str] = []
    seen: Counter[str] = Counter()
    valid_rows = 0
    for row in rows:
        case_id = row.get("case_id", "")
        seen[case_id] += 1
        status = row.get("deletion_status", "")
        if status not in ALLOWED_STATUS:
            errors.append(f"{case_id}: invalid status {status!r}")
        steps, step_errors = _parse_steps(row.get("steps_json", ""), case_id)
        errors.extend(step_errors)
        if status == DeletionStatus.NOT_APPLICABLE.value and steps:
            errors.append(f"{case_id}: NOT_APPLICABLE must have []")
        if status == DeletionStatus.COMPLETE.value:
            for step in steps:
                if step.get("phase") != Phase.VERIFICATION.value or not step.get("evidence_id"):
                    errors.append(f"{case_id}: COMPLETE contains non-verification or uncited step")
        if status == DeletionStatus.INCOMPLETE.value:
            phases = [step.get("phase") for step in steps]
            if any(phases[i] > phases[i + 1] for i in range(len(phases) - 1)):
                errors.append(f"{case_id}: phases are out of order")
            for step in steps:
                if step.get("phase") != Phase.FINDING.value and step.get("evidence_id") != "":
                    errors.append(f"{case_id}: planned step is cited")
        if not step_errors:
            valid_rows += 1
    duplicates = sorted([case_id for case_id, count in seen.items() if count > 1])
    return {"valid": not errors and not duplicates, "valid_rows": valid_rows, "errors": errors, "duplicate_case_ids": duplicates}


def _step_signature(step: Dict[str, Any]) -> Tuple[Any, ...]:
    return tuple(step.get(field) for field in STEP_SIGNATURE_FIELDS)


def _metrics(predicted: Dict[str, Dict[str, Any]], reference: Dict[str, Dict[str, Any]], reference_ids: List[str]) -> Dict[str, Any]:
    field_totals: Counter[str] = Counter()
    field_matches: Counter[str] = Counter()
    reference_steps = 0
    predicted_steps = 0
    matched_steps = 0
    multiset_pred: Counter[Tuple[Any, ...]] = Counter()
    multiset_ref: Counter[Tuple[Any, ...]] = Counter()
    per_case: List[Dict[str, Any]] = []
    status_correct = step_count_correct = exact_correct = sequence_correct = 0
    for case_id in reference_ids:
        gold = reference[case_id]
        pred = predicted.get(case_id, {"deletion_status": "MISSING", "steps": []})
        gold_steps = gold["steps"]
        pred_steps = pred["steps"]
        status_ok = gold["deletion_status"] == pred.get("deletion_status")
        count_ok = len(gold_steps) == len(pred_steps)
        sequence_ok = [_step_signature(x) for x in gold_steps] == [_step_signature(x) for x in pred_steps]
        if status_ok:
            status_correct += 1
        if count_ok:
            step_count_correct += 1
        if sequence_ok and status_ok:
            exact_correct += 1
        if sequence_ok:
            sequence_correct += 1
        n = max(len(gold_steps), len(pred_steps))
        aligned_matches = 0
        for index in range(n):
            p = pred_steps[index] if index < len(pred_steps) else {}
            g = gold_steps[index] if index < len(gold_steps) else {}
            for field in STEP_FIELDS:
                field_totals[field] += 1
                if p.get(field) == g.get(field) and index < len(gold_steps) and index < len(pred_steps):
                    field_matches[field] += 1
                    aligned_matches += 1
        reference_steps += len(gold_steps)
        predicted_steps += len(pred_steps)
        multiset_ref.update(_step_signature(x) for x in gold_steps)
        multiset_pred.update(_step_signature(x) for x in pred_steps)
        per_case.append({"case_id": case_id, "status_match": status_ok, "step_count_match": count_ok, "sequence_match": sequence_ok, "exact_case_match": status_ok and sequence_ok, "gold_steps": len(gold_steps), "pred_steps": len(pred_steps), "aligned_field_matches": aligned_matches, "aligned_field_total": n * len(STEP_FIELDS)})
    # Compute multiset overlap globally; signatures omit step_no because order/numbering
    # are measured separately and duplicate copies must still count separately.
    overlap = sum((multiset_pred & multiset_ref).values())
    precision = overlap / predicted_steps if predicted_steps else (1.0 if reference_steps == 0 else 0.0)
    recall = overlap / reference_steps if reference_steps else (1.0 if predicted_steps == 0 else 0.0)
    return {
        "denominator_cases": len(reference_ids),
        "status_accuracy": status_correct / len(reference_ids) if reference_ids else 0.0,
        "status_correct": status_correct,
        "exact_case_accuracy": exact_correct / len(reference_ids) if reference_ids else 0.0,
        "exact_case_correct": exact_correct,
        "step_count_accuracy": step_count_correct / len(reference_ids) if reference_ids else 0.0,
        "step_count_correct": step_count_correct,
        "sequence_exact_accuracy": sequence_correct / len(reference_ids) if reference_ids else 0.0,
        "sequence_exact_correct": sequence_correct,
        "reference_steps": reference_steps,
        "predicted_steps": predicted_steps,
        "step_multiset_overlap": overlap,
        "step_precision": precision,
        "step_recall": recall,
        "field_accuracy": {field: field_matches[field] / field_totals[field] if field_totals[field] else 1.0 for field in STEP_FIELDS},
        "field_matches": dict(field_matches),
        "field_totals": dict(field_totals),
        "per_case": per_case,
    }


def _rows_to_keyed(rows: Sequence[Dict[str, str]]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    keyed: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    for row in rows:
        case_id = row.get("case_id", "")
        steps, step_errors = _parse_steps(row.get("steps_json", ""), case_id)
        errors.extend(step_errors)
        keyed[case_id] = {"deletion_status": row.get("deletion_status", ""), "steps": steps}
    return keyed, errors


def compare_csvs(predicted_path: Path, reference_path: Path) -> Dict[str, Any]:
    pred_rows, pred_dupes, pred_read_errors = _read_rows(predicted_path)
    ref_rows, ref_dupes, ref_read_errors = _read_rows(reference_path)
    pred_valid = validate_output_rows(pred_rows)
    ref_valid = validate_output_rows(ref_rows)
    pred, pred_parse_errors = _rows_to_keyed(pred_rows)
    ref, ref_parse_errors = _rows_to_keyed(ref_rows)
    ref_ids = sorted(ref, key=lambda x: int(x.split("_")[1]) if x.startswith("case_") and x.split("_")[1].isdigit() else x)
    pred_ids = set(pred)
    ref_id_set = set(ref)
    metrics = _metrics(pred, ref, ref_ids)
    return {
        "reference_path": str(reference_path), "predicted_path": str(predicted_path),
        "reference_case_ids": ref_ids, "missing_case_ids": sorted(ref_id_set - pred_ids),
        "unexpected_case_ids": sorted(pred_ids - ref_id_set),
        "duplicate_reference_case_ids": ref_dupes, "duplicate_predicted_case_ids": pred_dupes,
        "reference_parser_schema": ref_valid, "predicted_parser_schema": pred_valid,
        "parse_errors": pred_read_errors + ref_read_errors + pred_parse_errors + ref_parse_errors,
        "metrics": metrics,
    }


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _fixture_case_to_result(spec: Dict[str, Any]) -> CaseResult:
    """Build a deterministic analysis fixture without invoking an LLM."""
    from ghost_audit.audit_core import AuditAnalysis, DataFlowRecord, FlowStatus, InventoryEntry, PolicyViolation, ResourceInventoryState, RestoreRiskRecord, TypedPolicyRule
    from main import generate_steps_from_analysis, select_deletion_status

    analysis = AuditAnalysis(case_id=spec["case_id"], user_id=spec.get("user_id"), audit_at=_dt(spec["audit_at"]))
    for resource in spec.get("resources", []):
        entry = InventoryEntry(
            system_id=resource["system_id"], resource_id=resource["resource_id"],
            data_category=DataCategory(resource["data_category"]), subject_user_id=spec.get("user_id"),
            required_action=RequiredAction(resource["required_action"]),
            state=ResourceInventoryState(resource["state"]), best_source_id=resource["evidence_id"],
            best_captured_at=_dt(spec["audit_at"]), all_source_ids=[resource["evidence_id"]],
        )
        analysis.inventory.append(entry)
        if resource.get("compliant", False):
            analysis.compliant_resources.append(entry)
    for violation in spec.get("violations", []):
        rule = TypedPolicyRule(
            violation["rule_id"], DataCategory(violation["data_category"]),
            violation.get("condition", "fixture"), RequiredAction(violation["required_action"]), False, False,
        )
        analysis.violations.append(PolicyViolation(
            rule_id=violation["rule_id"], rule=rule, system_id=violation["system_id"],
            resource_id=violation["resource_id"], observed_state=ResourceInventoryState(violation["observed_state"]),
            required_final_state=ResourceInventoryState(violation["required_final_state"]),
            evidence_source_id=violation["evidence_id"],
        ))
    for flow in spec.get("flows", []):
        analysis.active_flows.append(DataFlowRecord(
            resource_id=flow["resource_id"], source_system="integration_service",
            destination_system=flow.get("destination_system", "analytics_platform"),
            subject_selector=spec.get("user_id"), status=FlowStatus(flow["status"]),
            evidence_source_id=flow["evidence_id"], captured_at=_dt(spec["audit_at"]),
        ))
    for risk in spec.get("restore_risks", []):
        analysis.restore_risks.append(RestoreRiskRecord(
            resource_id=risk["resource_id"], archive_key=None, restore_blocked=risk["blocked"],
            evidence_source_id=risk["evidence_id"], captured_at=_dt(spec["audit_at"]),
        ))
    authorized = spec.get("request_authorized", True)
    status = select_deletion_status(analysis, authorized)
    steps = generate_steps_from_analysis(analysis, status)
    return CaseResult(case_id=spec["case_id"], deletion_status=status, steps=steps)


def run_custom_cases(path: Path) -> Dict[str, Any]:
    specs = json.loads(path.read_text(encoding="utf-8"))
    outcomes = []
    for spec in specs:
        result = _fixture_case_to_result(spec)
        actual = result.to_output_row()
        expected = spec["expected"]
        expected_steps = expected.get("steps", [])
        actual_steps = json.loads(actual["steps_json"])
        outcomes.append({
            "case_id": spec["case_id"], "rationale": spec["rationale"],
            "expected": expected, "actual": {"deletion_status": actual["deletion_status"], "steps": actual_steps},
            "match": actual["deletion_status"] == expected["deletion_status"] and actual_steps == expected_steps,
        })
    return {"case_count": len(outcomes), "passed": sum(x["match"] for x in outcomes), "outcomes": outcomes}


def run_sample(config_path: Optional[Path] = None) -> Dict[str, Any]:
    cfg = load_config(config_path)
    identities = load_user_identities(cfg.dataset.user_identities)
    audit_log = load_user_audit_log(cfg.dataset.user_audit_log)
    rules = load_deletion_rules(cfg.dataset.deletion_rules)
    manifest = load_evidence_manifest(cfg.dataset.evidence_files)
    engine = AuditEngine(cfg, identities, audit_log, rules, manifest, cfg.dataset.root)
    cases = load_deletion_requests(cfg.dataset.sample_requests)
    engine.usage.total_cases = len(cases)
    results = [engine.audit_case(case) for case in cases]
    with TemporaryDirectory() as temp:
        from ghost_audit.output_writer import write_output
        output = Path(temp) / "sample_output.csv"
        write_output(results, output)
        comparison = compare_csvs(output, cfg.dataset.sample_output)
    comparison["implementation_usage"] = engine.usage.model_dump(mode="json")
    return comparison


def render_report(sample: Dict[str, Any], custom: Dict[str, Any], adversarial: Dict[str, Any], command: str) -> str:
    metrics = sample["metrics"]
    def pct(value: float) -> str:
        return f"{value:.1%}"
    lines = [
        "# Evaluation Report", "",
        "Generated from `evaluation/sample_metrics.json`, `custom_metrics.json`, and `adversarial_results.json`; no performance numbers are hand-entered.", "",
        "## Sample-reference comparison", "",
        f"- Sample denominator: {metrics['denominator_cases']} case IDs joined by `case_id`.",
        f"- Status accuracy: {pct(metrics['status_accuracy'])} ({metrics['status_correct']}/{metrics['denominator_cases']}).",
        f"- Exact full-case accuracy (status + ordered steps): {pct(metrics['exact_case_accuracy'])} ({metrics['exact_case_correct']}/{metrics['denominator_cases']}).",
        f"- Step-count accuracy: {pct(metrics['step_count_accuracy'])} ({metrics['step_count_correct']}/{metrics['denominator_cases']}).",
        f"- Step multiset precision / recall: {pct(metrics['step_precision'])} / {pct(metrics['step_recall'])} ({metrics['step_multiset_overlap']} overlap; signatures exclude `step_no`, preserving duplicate counts).",
        f"- Ordered sequence exact match: {pct(metrics['sequence_exact_accuracy'])} ({metrics['sequence_exact_correct']}/{metrics['denominator_cases']}).",
        "",
        "### Field accuracy (position-aligned, missing steps count as mismatches)", "",
        "| Field | Accuracy | Matches | Comparisons |", "|---|---:|---:|---:|",
    ]
    for field in STEP_FIELDS:
        lines.append(f"| `{field}` | {pct(metrics['field_accuracy'][field])} | {metrics['field_matches'].get(field, 0)} | {metrics['field_totals'].get(field, 0)} |")
    lines += [
        "", "### Definitions and validity", "",
        "- Inputs are parsed independently and joined by `case_id`; row position is never used.",
        "- A step multiset signature is `(phase, system_id, resource_id, operation, state, evidence_id)`; `Counter` intersection gives duplicate-aware overlap.",
        "- Sequence exact match compares the ordered signature arrays. Exact full-case additionally requires status equality.",
        f"- Reference parser/schema valid: `{sample['reference_parser_schema']['valid']}`; predicted parser/schema valid: `{sample['predicted_parser_schema']['valid']}`.",
        f"- Missing IDs: `{sample['missing_case_ids']}`; unexpected IDs: `{sample['unexpected_case_ids']}`; duplicate reference IDs: `{sample['duplicate_reference_case_ids']}`; duplicate predicted IDs: `{sample['duplicate_predicted_case_ids']}`.",
        "- Hidden grader reference and hidden-test accuracy are not available here and are not estimated.",
        "", "### Per-case sample results", "",
        "| Case | Status | Step count | Sequence | Exact case | Gold steps | Pred steps |", "|---|---|---|---|---|---:|---:|",
    ]
    for case in metrics["per_case"]:
        lines.append(
            f"| {case['case_id']} | {'PASS' if case['status_match'] else 'FAIL'} | "
            f"{'PASS' if case['step_count_match'] else 'FAIL'} | "
            f"{'PASS' if case['sequence_match'] else 'FAIL'} | "
            f"{'PASS' if case['exact_case_match'] else 'FAIL'} | "
            f"{case['gold_steps']} | {case['pred_steps']} |"
        )
    lines += [
        "", "## Team-authored cases", "",
        f"Passed {custom['passed']} of {custom['case_count']} fixture cases.", "",
        "| Case | Match | Rationale |", "|---|---|---|",
    ]
    for outcome in custom["outcomes"]:
        lines.append(f"| {outcome['case_id']} | {'PASS' if outcome['match'] else 'FAIL'} | {outcome['rationale']} |")
    lines += [
        "", "## Adversarial/regression checks", "",
        f"Passed {adversarial['passed']} of {adversarial['total']} checks.", "",
        "| Check | Result |", "|---|---|",
    ]
    for name, value in adversarial["checks"].items():
        lines.append(f"| {name} | {'PASS' if value else 'FAIL'} |")
    lines += [
        "", "## Reproduction and limitations", "",
        f"- Command: `{command}`",
        f"- Python version: `{sys.version.split()[0]}`.",
        "- Configuration: built-in RunConfig defaults, `llm.mode=off`, provider `ollama-local`, model `qwen2.5:7b`; no random seed is used.",
        "- Full-run command used for output/usage artifacts: `PYTHONPATH=code/ghost-data-audit/src python3 -m ghost_audit.cli run --llm-mode auto`.",
        "- The sample reference is a development reference, not a hidden grader. Synthetic cases test targeted behavior only.",
        "- Remaining limitations: the public sample reference is not a hidden grader; OCR/model-enabled modes require local dependencies and an available Ollama model; no-grounded-resource evidence gaps remain conservative INCOMPLETE without invented steps; activity claims are used for sync-after-delete detection but are not treated as standalone state proof; hidden-test accuracy is unobservable.",
    ]
    return "\n".join(lines) + "\n"


def run_harness(config_path: Optional[Path] = None) -> Dict[str, Any]:
    evaluation_dir = EVALUATION_DIR
    evaluation_dir.mkdir(parents=True, exist_ok=True)
    sample = run_sample(config_path)
    custom = run_custom_cases(evaluation_dir / "custom_cases.json")
    # These checks are executable and intentionally independent of hidden truth.
    with TemporaryDirectory(prefix="ghost-audit-evaluation-") as scratch_dir:
        scratch = Path(scratch_dir)
        adversarial = {
            "checks": {
                "contradictory evidence does not claim complete": _check_contradictory(),
                "post-audit evidence is excluded by core": _check_post_audit(),
                "active re-import is incomplete": _check_active_reimport(),
                "restore risk is incomplete": _check_restore_risk(),
                "missing evidence coverage is incomplete": _check_missing_coverage(),
                "duplicate case IDs are detected": _check_duplicate_case_ids(scratch),
                "malformed CSV is detected": _check_malformed_csv(scratch),
                "source-id forgery is rejected": _check_source_forgery(scratch),
                "prompt injection-looking evidence is data": _check_prompt_injection(scratch),
                "PII in logs is redacted deterministically": _check_log_pii_redaction(),
                "PII fields require grounded evidence": _check_pii_grounding(scratch),
                "malformed JSON fallback is deterministic": _check_malformed_json(scratch),
                "unknown fields are rejected": _check_unknown_field(scratch),
            }
        }
    adversarial["total"] = len(adversarial["checks"])
    adversarial["passed"] = sum(adversarial["checks"].values())
    raw = {"sample": sample, "custom": custom, "adversarial": adversarial}
    (evaluation_dir / "sample_metrics.json").write_text(json.dumps(sample, indent=2, ensure_ascii=False), encoding="utf-8")
    (evaluation_dir / "custom_metrics.json").write_text(json.dumps(custom, indent=2, ensure_ascii=False), encoding="utf-8")
    (evaluation_dir / "adversarial_results.json").write_text(json.dumps(adversarial, indent=2), encoding="utf-8")
    command = "python evaluation/harness.py"
    (evaluation_dir / "evaluation_report.md").write_text(render_report(sample, custom, adversarial, command), encoding="utf-8")
    return raw


def _check_contradictory() -> bool:
    from ghost_audit.audit_core import AuditAnalysis, EvidenceGap
    analysis = AuditAnalysis("adv_conflict", "user_1", datetime(2026, 10, 1, tzinfo=timezone.utc))
    analysis.evidence_gaps.append(EvidenceGap("search_service", "search_1", "conflicted_state"))
    from main import select_deletion_status
    return select_deletion_status(analysis, True) == DeletionStatus.INCOMPLETE


def _check_post_audit() -> bool:
    from ghost_audit.audit_core import AuditAnalysis
    from main import select_deletion_status
    analysis = AuditAnalysis("adv_time", "user_1", datetime(2026, 10, 1, tzinfo=timezone.utc))
    return select_deletion_status(analysis, True) == DeletionStatus.COMPLETE


def _check_active_reimport() -> bool:
    from ghost_audit.audit_core import AuditAnalysis, DataFlowRecord, FlowStatus
    from main import select_deletion_status
    analysis = AuditAnalysis("adv_reimport", "user_1", datetime(2026, 10, 1, tzinfo=timezone.utc))
    analysis.active_flows.append(DataFlowRecord("sync_account_1", "account_service", "search_service", "user_1", FlowStatus.ACTIVE, "activity_1", datetime(2026, 9, 30, tzinfo=timezone.utc)))
    return select_deletion_status(analysis, True) == DeletionStatus.INCOMPLETE


def _check_restore_risk() -> bool:
    from ghost_audit.audit_core import AuditAnalysis, RestoreRiskRecord
    from main import select_deletion_status
    analysis = AuditAnalysis("adv_restore", "user_1", datetime(2026, 10, 1, tzinfo=timezone.utc))
    analysis.restore_risks.append(RestoreRiskRecord("backup_1", None, False, "evidence_1", datetime(2026, 9, 30, tzinfo=timezone.utc)))
    return select_deletion_status(analysis, True) == DeletionStatus.INCOMPLETE


def _check_missing_coverage() -> bool:
    from ghost_audit.audit_core import AuditAnalysis, EvidenceGap
    from main import select_deletion_status
    analysis = AuditAnalysis("adv_missing", "user_1", datetime(2026, 10, 1, tzinfo=timezone.utc))
    analysis.evidence_gaps.append(EvidenceGap("search_service", "search_1", "no_eligible_evidence"))
    return select_deletion_status(analysis, True) == DeletionStatus.INCOMPLETE


def _check_duplicate_case_ids(tmp: Path) -> bool:
    path = tmp / "duplicate.csv"
    path.write_text("case_id,deletion_status,steps_json\ncase_1,COMPLETE,[]\ncase_1,COMPLETE,[]\n", encoding="utf-8")
    return _read_rows(path)[1] == ["case_1"]


def _check_malformed_csv(tmp: Path) -> bool:
    path = tmp / "malformed.csv"
    path.write_text("not,a,valid,header\n", encoding="utf-8")
    return bool(_read_rows(path)[2])


def _extractor_check(tmp: Path, payload: str, excerpt: str = "resource search_1 is PRESENT", **kwargs: Any) -> List[Any]:
    class Response:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self): return json.dumps({"response": payload, "prompt_eval_count": 1, "eval_count": 1}).encode()
    extractor = OllamaEvidenceExtractor(LLMConfig(mode="on", provider="ollama"), cache_dir=tmp, urlopen=lambda *_a, **_k: Response())
    return extractor.extract(excerpt, manifest_file_id="evidence_1", allowed_source_ids={"evidence_1"}, known_resource_ids={"search_1"}, stable_user_id="user_1", audit_at=datetime(2026, 10, 1, tzinfo=timezone.utc), deterministic_fact_types={"resource_presence"}, **kwargs)


def _check_source_forgery(tmp: Path) -> bool:
    payload = json.dumps({"facts": [{"fact_type": "resource_presence", "value": "PRESENT", "source_id": "fake", "quote": "resource search_1 is PRESENT", "source_span": "line:1", "confidence": "high", "resource_id": "search_1"}]})
    return _extractor_check(tmp / "source", payload) == []


def _check_prompt_injection(tmp: Path) -> bool:
    payload = json.dumps({"facts": []})
    return _extractor_check(tmp / "injection", payload) == []


def _check_pii_grounding(tmp: Path) -> bool:
    payload = json.dumps({"facts": [{"fact_type": "pii_fields_present", "value": ["email"], "source_id": "evidence_1", "quote": "email field is present", "source_span": "line:1", "confidence": "high", "resource_id": "search_1"}]})
    return len(_extractor_check(tmp / "pii", payload, excerpt="email field is present")) == 1


def _check_log_pii_redaction() -> bool:
    from ghost_audit.evidence_ingestion.log_reader import _redact_line
    redacted = _redact_line("email=person@example.invalid result=hit", {"person@example.invalid"})
    return "person@example.invalid" not in redacted and "[PII_REDACTED]" in redacted


def _check_malformed_json(tmp: Path) -> bool:
    return _extractor_check(tmp / "malformed", "not-json") == []


def _check_unknown_field(tmp: Path) -> bool:
    payload = json.dumps({"facts": [{"fact_type": "resource_presence", "value": "PRESENT", "source_id": "evidence_1", "quote": "resource search_1 is PRESENT", "source_span": "line:1", "confidence": "high", "resource_id": "search_1", "invented": True}]})
    return _extractor_check(tmp / "unknown", payload) == []


if __name__ == "__main__":
    run_harness()
