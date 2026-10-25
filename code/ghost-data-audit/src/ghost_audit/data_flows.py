"""
data_flows.py — Extract DataFlowState and RestoreRisk objects from evidence facts.

Input contract:
    extract_data_flows(facts: List[EvidenceFact]) -> List[DataFlowState]
    extract_restore_risks(facts: List[EvidenceFact]) -> List[RestoreRisk]
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from .schemas import (
    DataFlowState,
    EvidenceFact,
    RecordState,
    RestoreRisk,
)

logger = logging.getLogger(__name__)


def extract_data_flows(
    facts: List[EvidenceFact],
    user_id: str,
) -> List[DataFlowState]:
    """
    Build DataFlowState objects from all EvidenceFacts for data_flow_<N> resources.

    Uses the most recent eligible fact per resource_id.
    """
    # Group by resource_id, keep most recent
    latest: Dict[str, EvidenceFact] = {}
    for fact in facts:
        if not fact.resource_id.startswith("data_flow"):
            continue
        existing = latest.get(fact.resource_id)
        if existing is None or fact.captured_at > existing.captured_at:
            latest[fact.resource_id] = fact

    states: List[DataFlowState] = []
    for resource_id, fact in latest.items():
        # enabled = True when state is PRESENT (active) or ACTIVE
        # disabled = state is DISABLED
        enabled = fact.observed_state not in (RecordState.DISABLED, RecordState.ABSENT)

        # Try to extract connector metadata from raw_value
        connector_name: Optional[str] = None
        subject_selector: Optional[str] = None
        if fact.raw_value:
            import json as _json
            try:
                rec = _json.loads(fact.raw_value)
                connector_name = rec.get("connector_name")
                subject_selector = rec.get("subject_selector")
            except Exception:
                pass

        states.append(DataFlowState(
            user_id=user_id,
            resource_id=resource_id,
            connector_name=connector_name,
            subject_selector=subject_selector,
            enabled=enabled,
            best_evidence_file_id=fact.file_id,
            best_evidence_captured_at=fact.captured_at,
        ))

    return states


def extract_restore_risks(
    facts: List[EvidenceFact],
    user_id: str,
) -> List[RestoreRisk]:
    """
    Build RestoreRisk objects from all EvidenceFacts for backup_<N> resources.

    restore_allowed=True → risk (backup can restore data).
    restore_allowed=False → already blocked (no finding needed, but should verify).
    """
    latest: Dict[str, EvidenceFact] = {}
    for fact in facts:
        if not fact.resource_id.startswith("backup"):
            continue
        existing = latest.get(fact.resource_id)
        if existing is None or fact.captured_at > existing.captured_at:
            latest[fact.resource_id] = fact

    risks: List[RestoreRisk] = []
    for resource_id, fact in latest.items():
        restore_allowed = fact.observed_state not in (
            RecordState.BLOCKED, RecordState.DISABLED, RecordState.ABSENT
        )

        # Try to extract archive_path
        archive_path: Optional[str] = None
        if fact.raw_value:
            import json as _json
            try:
                rec = _json.loads(fact.raw_value)
                archive_path = rec.get("archive_path") or rec.get("archive_key")
            except Exception:
                pass

        risks.append(RestoreRisk(
            user_id=user_id,
            resource_id=resource_id,
            archive_path=archive_path,
            restore_allowed=restore_allowed,
            best_evidence_file_id=fact.file_id,
            best_evidence_captured_at=fact.captured_at,
        ))

    return risks
