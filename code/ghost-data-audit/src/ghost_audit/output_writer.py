"""
output_writer.py — Write CaseResult list to output.csv.

Input contract:
    write_output(results: List[CaseResult], output_path: Path) -> None

Output:
    CSV with header: case_id,deletion_status,steps_json
    Rows sorted by numeric case_id.
    steps_json is a valid compact JSON array.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional, Set

from .schemas import CaseResult, DeletionStatus, OPERATION_STATE_MAP, PHASE_OPERATIONS, Phase, Operation

logger = logging.getLogger(__name__)

OUTPUT_FIELDS = ["case_id", "deletion_status", "steps_json"]


def numeric_case_key(case_id: str) -> tuple[int, str]:
    """Sort case IDs by numeric suffix, never raw string order."""
    prefix, separator, suffix = case_id.rpartition("_")
    if not separator or not suffix.isdigit():
        raise ValueError(f"case_id must have a numeric suffix: {case_id!r}")
    return int(suffix), prefix


def write_output(
    results: List[CaseResult],
    output_path: Path,
    expected_case_ids: Optional[Iterable[str]] = None,
    allowed_evidence_ids: Optional[Set[str]] = None,
) -> None:
    """
    Write all CaseResult objects to output_path as a CSV file.

    The file is created (or overwritten) at output_path.
    Rows are sorted by the numeric part of case_id.

    Parameters
    ----------
    results : List[CaseResult]
    output_path : Path
        Destination file path (must be writable; parent directory must exist).
    """
    if not results:
        logger.warning("write_output called with empty results list")

    # Sort by numeric case_id
    sorted_results = sorted(results, key=lambda r: numeric_case_key(r.case_id))

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Validate the serialized temporary file before replacing the destination.
    # This makes partial or malformed output impossible at the final path.
    with tempfile.NamedTemporaryFile(
        mode="w", newline="", encoding="utf-8", dir=output_path.parent,
        prefix=f".{output_path.name}.", suffix=".tmp", delete=False,
    ) as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=OUTPUT_FIELDS,
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        writer.writeheader()
        for result in sorted_results:
            writer.writerow(result.to_output_row())
        temporary_path = Path(fh.name)

    errors = validate_output(
        temporary_path,
        list(expected_case_ids) if expected_case_ids is not None else None,
        allowed_evidence_ids=allowed_evidence_ids,
    )
    if errors:
        temporary_path.unlink(missing_ok=True)
        raise ValueError("Refusing to publish invalid output: " + "; ".join(errors[:10]))
    os.replace(temporary_path, output_path)

    logger.info("Wrote %d rows to %s", len(sorted_results), output_path)


def validate_output(
    output_path: Path,
    expected_case_ids: Optional[List[str]] = None,
    allowed_evidence_ids: Optional[Set[str]] = None,
) -> List[str]:
    """
    Validate an existing output.csv file.

    Checks:
      - Header is correct
      - Exactly one row per expected case_id
      - steps_json is valid JSON
      - deletion_status is a valid value
      - step_no values are consecutive from 1

    Returns a list of error strings (empty = valid).
    """
    errors: List[str] = []
    allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

    if not output_path.exists():
        return [f"Output file not found: {output_path}"]

    with open(output_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != OUTPUT_FIELDS:
            errors.append(
                f"Wrong header: expected ['case_id','deletion_status','steps_json'], "
                f"got {reader.fieldnames}"
            )
        rows = list(reader)

    written_ids = [r.get("case_id", "") for r in rows]
    expected_set = set(expected_case_ids or written_ids)
    written_set = set(written_ids)

    if len(written_ids) != len(written_set):
        errors.append("Duplicate case_ids in output")
    if expected_case_ids is not None and written_ids != sorted(expected_case_ids, key=numeric_case_key):
        errors.append("Output case_ids are not in numeric-suffix ascending canonical order")

    missing = expected_set - written_set
    extra = written_set - expected_set
    if missing:
        errors.append(f"Missing case_ids: {sorted(missing)[:10]}")
    if extra:
        errors.append(f"Unexpected case_ids: {sorted(extra)[:10]}")

    for row in rows:
        cid = row.get("case_id", "?")
        status = row.get("deletion_status", "")
        steps_raw = row.get("steps_json", "")

        if status not in allowed_statuses:
            errors.append(f"[{cid}] Invalid deletion_status: {status!r}")

        try:
            steps = json.loads(steps_raw)
        except json.JSONDecodeError as e:
            errors.append(f"[{cid}] Invalid steps_json: {e}")
            continue

        if not isinstance(steps, list):
            errors.append(f"[{cid}] steps_json must be a JSON array")
            continue

        if status == DeletionStatus.NOT_APPLICABLE.value and steps:
            errors.append(f"[{cid}] NOT_APPLICABLE must serialize as []")
        if status == DeletionStatus.COMPLETE.value and not steps:
            errors.append(f"[{cid}] COMPLETE must contain verification steps")

        phases = []
        previous_sort_key = None

        for i, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(f"[{cid}] step {i} is not an object")
                continue
            if set(step) != {
                "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
            }:
                errors.append(f"[{cid}] step {i} has an invalid schema")
                continue
            if step.get("step_no") != i:
                errors.append(
                    f"[{cid}] step_no sequencing error at position {i}: "
                    f"got {step.get('step_no')}"
                )
                break
            try:
                phase = Phase(step["phase"])
                operation = Operation(step["operation"])
                expected_state = OPERATION_STATE_MAP[operation].value
                if step["state"] != expected_state:
                    errors.append(f"[{cid}] step {i} has invalid operation/state pair")
                if operation not in PHASE_OPERATIONS[phase]:
                    errors.append(f"[{cid}] step {i} has invalid operation/phase pair")
                phase_order = {p: n for n, p in enumerate(Phase.order())}
                op_order = {
                    Phase.FINDING: {
                        Operation.REPORT_REMAINING_RECORD: 0, Operation.REPORT_EXPOSED_PII: 1,
                        Operation.REPORT_ACTIVE_DATA_FLOW: 2, Operation.REPORT_RESTORE_RISK: 3,
                    },
                    Phase.REMEDIATION: {
                        Operation.DISABLE_DATA_FLOW: 0, Operation.BLOCK_RESTORE: 1,
                        Operation.DELETE_RECORD: 2, Operation.REDACT_RECORD: 3, Operation.ANONYMIZE_RECORD: 4,
                    },
                    Phase.VERIFICATION: {
                        Operation.VERIFY_RECORD_ABSENT: 0, Operation.VERIFY_RECORD_PRESENT: 1,
                        Operation.VERIFY_RECORD_REDACTED: 2, Operation.VERIFY_RECORD_ANONYMIZED: 3,
                        Operation.VERIFY_DATA_FLOW_DISABLED: 4, Operation.VERIFY_RESTORE_BLOCKED: 5,
                    },
                }
                sort_key = (phase_order[phase], op_order[phase][operation], step["system_id"], step["resource_id"])
                if previous_sort_key is not None and sort_key < previous_sort_key:
                    errors.append(f"[{cid}] step ordering is not canonical")
                previous_sort_key = sort_key
                phases.append(phase)
            except (KeyError, ValueError):
                errors.append(f"[{cid}] step {i} has unsupported phase/operation/state")
                continue

            evidence_id = step.get("evidence_id", "")
            if allowed_evidence_ids is not None and evidence_id and evidence_id not in allowed_evidence_ids:
                errors.append(f"[{cid}] step {i} cites unknown evidence_id")
            if status == DeletionStatus.COMPLETE.value:
                if phase != Phase.VERIFICATION or not evidence_id:
                    errors.append(f"[{cid}] COMPLETE must contain only cited verification steps")
            elif status == DeletionStatus.INCOMPLETE.value:
                if phase == Phase.FINDING and not evidence_id:
                    errors.append(f"[{cid}] actual finding must cite evidence_id")
                if phase != Phase.FINDING and evidence_id != "":
                    errors.append(f"[{cid}] planned/future INCOMPLETE steps must have empty evidence_id")

        if status == DeletionStatus.INCOMPLETE.value:
            phase_values = [p.value for p in phases]
            phase_numbers = [{"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}[p] for p in phase_values]
            if phase_numbers != sorted(phase_numbers):
                errors.append(f"[{cid}] INCOMPLETE phases are not FINDING/REMEDIATION/VERIFICATION")

    return errors
