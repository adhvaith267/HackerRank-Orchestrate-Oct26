"""
test_output.py — Unit tests for output_writer.py and evaluator.py.

Tests:
  - write_output produces correct CSV with correct header and sorted rows
  - validate_output detects missing cases, wrong header, bad JSON, bad step_no
  - evaluate() calculates correct accuracy metrics against gold
"""

import csv
import json
import pytest
from datetime import datetime, timezone
from pathlib import Path

from ghost_audit.output_writer import validate_output, write_output
from ghost_audit.schemas import (
    AuditStep,
    CaseResult,
    DeletionStatus,
    Operation,
    Phase,
    RecordState,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_complete_result(case_id: str, account_id: str, evidence_id: str) -> CaseResult:
    step = AuditStep(
        step_no=1,
        phase=Phase.VERIFICATION,
        system_id="account_service",
        resource_id=account_id,
        operation=Operation.VERIFY_RECORD_ABSENT,
        state=RecordState.ABSENT,
        evidence_id=evidence_id,
    )
    return CaseResult(
        case_id=case_id,
        deletion_status=DeletionStatus.COMPLETE,
        steps=[step],
    )


def _make_na_result(case_id: str) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        deletion_status=DeletionStatus.NOT_APPLICABLE,
        steps=[],
    )


# ---------------------------------------------------------------------------
# write_output tests
# ---------------------------------------------------------------------------

class TestWriteOutput:
    def test_writes_header(self, tmp_path):
        out = tmp_path / "output.csv"
        write_output([], out)
        with open(out, newline="") as fh:
            reader = csv.DictReader(fh)
            assert reader.fieldnames == ["case_id", "deletion_status", "steps_json"]

    def test_writes_sorted_rows(self, tmp_path):
        out = tmp_path / "output.csv"
        results = [
            _make_complete_result("case_100", "account_100", "evidence_01"),
            _make_complete_result("case_33", "account_033", "evidence_01"),
            _make_complete_result("case_550", "account_550", "evidence_01"),
        ]
        write_output(results, out)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        case_ids = [r["case_id"] for r in rows]
        assert case_ids == ["case_33", "case_100", "case_550"]

    def test_not_applicable_has_empty_steps(self, tmp_path):
        out = tmp_path / "output.csv"
        results = [_make_na_result("case_01")]
        write_output(results, out)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        assert json.loads(rows[0]["steps_json"]) == []
        assert rows[0]["deletion_status"] == "NOT_APPLICABLE"

    def test_steps_json_is_valid_json(self, tmp_path):
        out = tmp_path / "output.csv"
        results = [_make_complete_result("case_01", "account_001", "evidence_54")]
        write_output(results, out)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        steps = json.loads(rows[0]["steps_json"])
        assert isinstance(steps, list)
        assert steps[0]["step_no"] == 1
        assert steps[0]["phase"] == "VERIFICATION"

    def test_output_row_contains_required_keys(self, tmp_path):
        out = tmp_path / "output.csv"
        results = [_make_complete_result("case_01", "account_001", "evidence_54")]
        write_output(results, out)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        step = json.loads(rows[0]["steps_json"])[0]
        required = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
        assert required == set(step.keys())

    def test_creates_parent_directory(self, tmp_path):
        out = tmp_path / "subdir" / "output.csv"
        write_output([], out)
        assert out.exists()


# ---------------------------------------------------------------------------
# validate_output tests
# ---------------------------------------------------------------------------

class TestValidateOutput:
    def test_valid_output_no_errors(self, tmp_path):
        out = tmp_path / "output.csv"
        results = [
            _make_complete_result("case_01", "account_001", "evidence_54"),
            _make_na_result("case_02"),
        ]
        write_output(results, out)
        errors = validate_output(out, ["case_01", "case_02"])
        assert errors == []

    def test_missing_case_id_reported(self, tmp_path):
        out = tmp_path / "output.csv"
        results = [_make_complete_result("case_01", "account_001", "evidence_54")]
        write_output(results, out)
        errors = validate_output(out, ["case_01", "case_02"])  # case_02 missing
        assert any("Missing" in e for e in errors)

    def test_file_not_found_returns_error(self, tmp_path):
        errors = validate_output(tmp_path / "nonexistent.csv", ["case_01"])
        assert any("not found" in e.lower() for e in errors)

    def test_bad_step_no_detected(self, tmp_path):
        out = tmp_path / "output.csv"
        # Write manually with broken step numbering
        with open(out, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"])
            writer.writeheader()
            steps = [
                {"step_no": 1, "phase": "FINDING", "system_id": "s", "resource_id": "r",
                 "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "e_01"},
                {"step_no": 3, "phase": "REMEDIATION", "system_id": "s", "resource_id": "r",  # step_no=3, not 2
                 "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
            ]
            writer.writerow({
                "case_id": "case_01",
                "deletion_status": "INCOMPLETE",
                "steps_json": json.dumps(steps),
            })
        errors = validate_output(out, ["case_01"])
        assert any("step_no" in e.lower() or "sequencing" in e.lower() for e in errors)

    def test_invalid_json_in_steps(self, tmp_path):
        out = tmp_path / "output.csv"
        with open(out, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"])
            writer.writeheader()
            writer.writerow({
                "case_id": "case_01",
                "deletion_status": "INCOMPLETE",
                "steps_json": "not valid json",
            })
        errors = validate_output(out, ["case_01"])
        assert any("steps_json" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# evaluate() tests
# ---------------------------------------------------------------------------

class TestEvaluate:
    def test_perfect_match(self, tmp_path):
        from ghost_audit.evaluator import evaluate
        gold = tmp_path / "gold.csv"
        pred = tmp_path / "pred.csv"
        results = [_make_complete_result("case_01", "account_001", "evidence_54")]
        write_output(results, gold)
        write_output(results, pred)
        report = evaluate(pred, gold)
        assert report.status_accuracy == 1.0
        assert report.all_steps_accuracy == 1.0

    def test_status_mismatch(self, tmp_path):
        from ghost_audit.evaluator import evaluate
        gold = tmp_path / "gold.csv"
        pred = tmp_path / "pred.csv"
        gold_results = [_make_complete_result("case_01", "account_001", "evidence_54")]
        pred_results = [CaseResult(
            case_id="case_01",
            deletion_status=DeletionStatus.INCOMPLETE,
            steps=[AuditStep(
                step_no=1, phase=Phase.FINDING,
                system_id="account_service", resource_id="account_001",
                operation=Operation.REPORT_REMAINING_RECORD,
                state=RecordState.PRESENT, evidence_id="evidence_54",
            )],
        )]
        write_output(gold_results, gold)
        write_output(pred_results, pred)
        report = evaluate(pred, gold)
        assert report.status_accuracy == 0.0

    def test_missing_gold_file_returns_error(self, tmp_path):
        from ghost_audit.evaluator import evaluate
        pred = tmp_path / "pred.csv"
        write_output([], pred)
        report = evaluate(pred, tmp_path / "no_gold.csv")
        assert len(report.errors) > 0
