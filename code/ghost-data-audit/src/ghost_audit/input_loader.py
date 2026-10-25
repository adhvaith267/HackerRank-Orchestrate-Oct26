"""
input_loader.py — Load and validate all CSV inputs from the dataset.

Input contract:
    load_deletion_requests(path) -> List[RequestCase]
    load_user_identities(path)   -> List[Dict]   (raw rows, keyed by user_id)
    load_user_audit_log(path)    -> List[Dict]
    load_system_activity(path)   -> List[Dict]
    load_deletion_rules(path)    -> List[PolicyRule]
    load_evidence_manifest(path) -> List[EvidenceRef]

All paths are Path objects. Files are not modified.
Timestamps are parsed to UTC-aware datetimes.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, Dict, List

from .schemas import (
    EvidenceFormat,
    EvidenceRef,
    PolicyRule,
    RequestCase,
    _parse_utc,
)

logger = logging.getLogger(__name__)


def _read_csv(path: Path) -> List[Dict[str, str]]:
    """Read a CSV file and return rows as dicts, skipping blank rows."""
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}")
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return [row for row in reader if any(v.strip() for v in row.values())]


def load_deletion_requests(path: Path) -> List[RequestCase]:
    """
    Load deletion_requests.csv (or sample_deletion_requests.csv).

    Columns: case_id, email, requested_at, reported_status, reported_at,
             audit_at, request_text

    Returns rows sorted by case_id numeric part.
    """
    rows = _read_csv(path)
    cases: List[RequestCase] = []
    errors: List[str] = []
    for row in rows:
        try:
            req_at = _parse_utc(row["requested_at"])
            rep_at = _parse_utc(row["reported_at"])
            aud_at = _parse_utc(row["audit_at"])
            case = RequestCase(
                case_id=row["case_id"].strip(),
                email=row["email"].strip(),
                requested_at_raw=row["requested_at"].strip(),
                requested_at=req_at,
                reported_status=row["reported_status"].strip(),
                reported_at_raw=row["reported_at"].strip(),
                reported_at=rep_at,
                audit_at_raw=row["audit_at"].strip(),
                audit_at=aud_at,
                request_text=row["request_text"].strip(),
            )
            cases.append(case)
        except Exception as exc:
            errors.append(f"Row {row.get('case_id', '?')}: {exc}")

    if errors:
        for e in errors:
            logger.warning("load_deletion_requests: %s", e)

    # Sort by numeric case_id
    cases.sort(key=lambda c: int(c.case_id.split("_")[1]))
    logger.info("Loaded %d deletion requests from %s (%d errors)", len(cases), path, len(errors))
    return cases


def load_user_identities(path: Path) -> Dict[str, Dict[str, str]]:
    """
    Load user_identities.csv.

    Columns: user_id, name, email, phone, email_hash, updated_at

    Returns dict keyed by user_id. Email is lowercased for lookups.
    """
    rows = _read_csv(path)
    result: Dict[str, Dict[str, str]] = {}
    for row in rows:
        uid = row["user_id"].strip()
        result[uid] = {
            "user_id": uid,
            "name": row.get("name", "").strip(),
            "email": row.get("email", "").strip().lower(),
            "phone": row.get("phone", "").strip(),
            "email_hash": row.get("email_hash", "").strip().lower(),
            "updated_at": row.get("updated_at", "").strip(),
        }
    logger.info("Loaded %d user identities from %s", len(result), path)
    return result


def load_user_audit_log(path: Path) -> List[Dict[str, str]]:
    """
    Load user_audit_log.csv.

    Columns: audit_id, user_id, event_time, field_name, old_value, new_value

    Values are returned as-is except emails/hashes are lowercased.
    """
    rows = _read_csv(path)
    result: List[Dict[str, str]] = []
    for row in rows:
        field = row.get("field_name", "").strip()
        old_val = row.get("old_value", "").strip()
        new_val = row.get("new_value", "").strip()
        # Normalise email and email_hash fields
        if field in {"email", "email_hash"}:
            old_val = old_val.lower()
            new_val = new_val.lower()
        result.append({
            "audit_id": row["audit_id"].strip(),
            "user_id": row["user_id"].strip(),
            "event_time": row["event_time"].strip(),
            "field_name": field,
            "old_value": old_val,
            "new_value": new_val,
        })
    logger.info("Loaded %d audit log entries from %s", len(result), path)
    return result


def load_system_activity(path: Path) -> List[Dict[str, str]]:
    """
    Load system_activity.csv.

    Columns: activity_id, event_time, event_type, source_system,
             target_system, resource_id, reported_result, details

    Important: reported_result is a claim, not a verified fact.
    """
    rows = _read_csv(path)
    logger.info("Loaded %d system activity rows from %s", len(rows), path)
    return rows


def load_deletion_rules(path: Path) -> List[PolicyRule]:
    """
    Load deletion_rules.csv.

    Columns: rule_id, data_category, condition, required_action

    Returns 15 PolicyRule objects (or as many as are present).
    """
    rows = _read_csv(path)
    rules: List[PolicyRule] = []
    for row in rows:
        try:
            rule = PolicyRule(
                rule_id=row["rule_id"].strip(),
                data_category=row["data_category"].strip(),
                condition=row["condition"].strip(),
                required_action=row["required_action"].strip(),
            )
            rules.append(rule)
        except Exception as exc:
            logger.warning("load_deletion_rules row %s: %s", row.get("rule_id"), exc)
    logger.info("Loaded %d deletion rules from %s", len(rules), path)
    return rules


def load_evidence_manifest(path: Path) -> List[EvidenceRef]:
    """
    Load evidence_files.csv.

    Columns: file_id, file_path, origin, captured_at

    Returns 94 EvidenceRef objects sorted by file_id numeric part.
    """
    rows = _read_csv(path)
    refs: List[EvidenceRef] = []
    for row in rows:
        try:
            fp = row["file_path"].strip()
            ref = EvidenceRef(
                file_id=row["file_id"].strip(),
                file_path=fp,
                origin=row["origin"].strip(),
                captured_at_raw=row["captured_at"].strip(),
                captured_at=_parse_utc(row["captured_at"].strip()),
                format=fp,  # field_validator infers from extension
            )
            refs.append(ref)
        except Exception as exc:
            logger.warning("load_evidence_manifest row %s: %s", row.get("file_id"), exc)
    refs.sort(key=lambda r: int(r.file_id.split("_")[1]))
    logger.info("Loaded %d evidence manifest entries from %s", len(refs), path)
    return refs
