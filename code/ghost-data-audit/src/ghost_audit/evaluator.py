"""
evaluator.py — Compare generated output.csv against a gold/sample output.

Input contract:
    evaluate(predicted_path, gold_path) -> EvaluationReport
    EvaluationReport.to_markdown() -> str
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class StepMatch:
    case_id: str
    step_no: int
    field: str
    predicted: Any
    gold: Any
    match: bool


@dataclass
class CaseEval:
    case_id: str
    status_match: bool
    predicted_status: str
    gold_status: str
    n_gold_steps: int
    n_pred_steps: int
    step_matches: List[StepMatch] = field(default_factory=list)

    @property
    def step_count_match(self) -> bool:
        return self.n_gold_steps == self.n_pred_steps

    @property
    def all_steps_match(self) -> bool:
        return all(m.match for m in self.step_matches)

    @property
    def step_accuracy(self) -> float:
        if not self.step_matches:
            return 1.0 if self.n_gold_steps == 0 else 0.0
        return sum(1 for m in self.step_matches if m.match) / len(self.step_matches)


@dataclass
class EvaluationReport:
    total_cases: int = 0
    status_correct: int = 0
    status_accuracy: float = 0.0
    step_count_correct: int = 0
    step_count_accuracy: float = 0.0
    all_steps_correct: int = 0
    all_steps_accuracy: float = 0.0
    avg_step_field_accuracy: float = 0.0
    per_case: List[CaseEval] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            "# Evaluation Report\n",
            "## Summary\n",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Total cases evaluated | {self.total_cases} |",
            f"| Deletion status accuracy | {self.status_accuracy:.1%} ({self.status_correct}/{self.total_cases}) |",
            f"| Step count accuracy | {self.step_count_accuracy:.1%} ({self.step_count_correct}/{self.total_cases}) |",
            f"| Full step sequence accuracy | {self.all_steps_accuracy:.1%} ({self.all_steps_correct}/{self.total_cases}) |",
            f"| Avg step-field accuracy | {self.avg_step_field_accuracy:.1%} |",
            "",
            "## Per-case Results\n",
            "| case_id | Gold Status | Pred Status | Status ✓ | Gold Steps | Pred Steps | Step Acc |",
            "|---|---|---|---|---|---|---|",
        ]
        for ce in self.per_case:
            lines.append(
                f"| {ce.case_id} | {ce.gold_status} | {ce.predicted_status} "
                f"| {'✓' if ce.status_match else '✗'} "
                f"| {ce.n_gold_steps} | {ce.n_pred_steps} "
                f"| {ce.step_accuracy:.1%} |"
            )
        if self.errors:
            lines.append("\n## Errors\n")
            for e in self.errors:
                lines.append(f"- {e}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Step comparison helpers
# ---------------------------------------------------------------------------

_STEP_FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def _compare_steps(
    case_id: str,
    pred_steps: List[Dict],
    gold_steps: List[Dict],
) -> List[StepMatch]:
    """Compare predicted steps to gold steps positionally."""
    matches: List[StepMatch] = []
    n = max(len(pred_steps), len(gold_steps))
    for i in range(n):
        pred = pred_steps[i] if i < len(pred_steps) else {}
        gold = gold_steps[i] if i < len(gold_steps) else {}
        for field_name in _STEP_FIELDS:
            pv = pred.get(field_name)
            gv = gold.get(field_name)
            matches.append(StepMatch(
                case_id=case_id,
                step_no=i + 1,
                field=field_name,
                predicted=pv,
                gold=gv,
                match=(pv == gv),
            ))
    return matches


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

def evaluate(predicted_path: Path, gold_path: Path) -> EvaluationReport:
    """
    Compare a predicted output.csv against a gold output.csv.

    Both files must have columns: case_id, deletion_status, steps_json.
    Cases are matched by case_id (not row position).
    """
    report = EvaluationReport()

    def _read_csv_keyed(path: Path) -> Dict[str, Dict]:
        if not path.exists():
            report.errors.append(f"File not found: {path}")
            return {}
        with open(path, newline="", encoding="utf-8") as fh:
            return {r["case_id"]: r for r in csv.DictReader(fh)}

    gold_rows = _read_csv_keyed(gold_path)
    pred_rows = _read_csv_keyed(predicted_path)

    if report.errors:
        return report

    # Evaluate on gold cases only
    gold_ids = sorted(gold_rows.keys(), key=lambda c: int(c.split("_")[1]))
    report.total_cases = len(gold_ids)

    all_step_accs: List[float] = []

    for case_id in gold_ids:
        gold_row = gold_rows[case_id]
        pred_row = pred_rows.get(case_id)

        gold_status = gold_row.get("deletion_status", "")
        pred_status = pred_row.get("deletion_status", "") if pred_row else "MISSING"

        try:
            gold_steps: List[Dict] = json.loads(gold_row.get("steps_json", "[]"))
        except Exception:
            gold_steps = []

        try:
            pred_steps: List[Dict] = json.loads(pred_row.get("steps_json", "[]")) if pred_row else []
        except Exception:
            pred_steps = []

        status_match = gold_status == pred_status
        if status_match:
            report.status_correct += 1

        step_matches = _compare_steps(case_id, pred_steps, gold_steps)
        n_gold = len(gold_steps)
        n_pred = len(pred_steps)

        ce = CaseEval(
            case_id=case_id,
            status_match=status_match,
            predicted_status=pred_status,
            gold_status=gold_status,
            n_gold_steps=n_gold,
            n_pred_steps=n_pred,
            step_matches=step_matches,
        )
        report.per_case.append(ce)

        if ce.step_count_match:
            report.step_count_correct += 1
        if ce.all_steps_match:
            report.all_steps_correct += 1
        all_step_accs.append(ce.step_accuracy)

    # Compute summary metrics
    if report.total_cases:
        report.status_accuracy = report.status_correct / report.total_cases
        report.step_count_accuracy = report.step_count_correct / report.total_cases
        report.all_steps_accuracy = report.all_steps_correct / report.total_cases
        report.avg_step_field_accuracy = (
            sum(all_step_accs) / len(all_step_accs) if all_step_accs else 0.0
        )

    return report
