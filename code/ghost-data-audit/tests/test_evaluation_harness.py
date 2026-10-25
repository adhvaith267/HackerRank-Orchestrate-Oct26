"""Tests for join semantics, schema validation, and metric definitions."""

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

import harness  # noqa: E402


def _write(path: Path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)


def test_compare_joins_by_case_id_and_detects_duplicates(tmp_path):
    step = {"step_no": 1, "phase": "VERIFICATION", "system_id": "s", "resource_id": "r", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "e"}
    ref = tmp_path / "ref.csv"
    pred = tmp_path / "pred.csv"
    _write(ref, [{"case_id": "case_2", "deletion_status": "COMPLETE", "steps_json": json.dumps([step])}, {"case_id": "case_1", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}])
    _write(pred, [{"case_id": "case_1", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}, {"case_id": "case_1", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}])
    result = harness.compare_csvs(pred, ref)
    assert result["duplicate_predicted_case_ids"] == ["case_1"]
    assert result["missing_case_ids"] == ["case_2"]
    assert result["metrics"]["denominator_cases"] == 2


def test_multiset_metrics_count_duplicate_steps_and_sequence_separately(tmp_path):
    a = {"step_no": 1, "phase": "VERIFICATION", "system_id": "s", "resource_id": "r", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "e"}
    b = {**a, "step_no": 2, "resource_id": "r2"}
    ref = tmp_path / "ref.csv"
    pred = tmp_path / "pred.csv"
    _write(ref, [{"case_id": "case_1", "deletion_status": "COMPLETE", "steps_json": json.dumps([a, b])}])
    _write(pred, [{"case_id": "case_1", "deletion_status": "COMPLETE", "steps_json": json.dumps([b, a])}])
    result = harness.compare_csvs(pred, ref)
    assert result["metrics"]["step_precision"] == 1.0
    assert result["metrics"]["step_recall"] == 1.0
    assert result["metrics"]["sequence_exact_accuracy"] == 0.0
    assert result["metrics"]["exact_case_accuracy"] == 0.0


def test_schema_rejects_unknown_step_fields_and_not_applicable_steps(tmp_path):
    row = {"case_id": "case_1", "deletion_status": "NOT_APPLICABLE", "steps_json": json.dumps([{"step_no": 1, "phase": "FINDING", "system_id": "s", "resource_id": "r", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "e", "extra": 1}])}
    out = tmp_path / "out.csv"
    _write(out, [row])
    result = harness.validate_output_rows(list(csv.DictReader(out.open(newline="", encoding="utf-8"))))
    assert result["valid"] is False
    assert result["errors"]
