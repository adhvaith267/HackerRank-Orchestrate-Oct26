"""
temporal.py — Temporal reconstruction: determine resource state at audit_at.

Input contract:
    TemporalReconstructor(evidence_facts, audit_at)
    .get_state(user_id, system_id, resource_id) -> Optional[ResourceState]
    .get_all_states(user_id) -> List[ResourceState]

Rules (from DATA_DISCOVERY.md §6.5 and AGENTS.md §6.2):
  - Use only evidence with captured_at <= audit_at.
  - For each resource, use the most recent eligible evidence fact.
  - If a resource appears in a replica but not in primary, flag has_replica_drift=True.
  - Treat activity log reported_results as claims only; state comes from evidence facts.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from .schemas import (
    DataCategory,
    EvidenceFact,
    RecordState,
    ResourceState,
)

logger = logging.getLogger(__name__)


class TemporalReconstructor:
    """
    Reconstructs the state of every resource for a user at a given audit_at.

    Parameters
    ----------
    evidence_facts:
        All EvidenceFacts extracted for this user across all eligible evidence files.
        May include facts from multiple snapshots of the same resource.
    audit_at:
        The strict cutoff: only facts with captured_at <= audit_at are used.
    """

    def __init__(
        self,
        evidence_facts: List[EvidenceFact],
        audit_at: datetime,
    ) -> None:
        self._all_facts = evidence_facts
        self._audit_at = audit_at
        # Filter to eligible facts
        self._eligible = [
            f for f in evidence_facts if f.captured_at <= audit_at
        ]
        # Group: (system_id, resource_id) -> sorted list of eligible facts
        self._grouped: Dict[Tuple[str, str], List[EvidenceFact]] = defaultdict(list)
        for fact in self._eligible:
            self._grouped[(fact.system_id, fact.resource_id)].append(fact)
        # Sort each group by captured_at descending (most recent first)
        for key in self._grouped:
            self._grouped[key].sort(key=lambda f: f.captured_at, reverse=True)

    def get_state(
        self, system_id: str, resource_id: str
    ) -> Optional[ResourceState]:
        """
        Return the ResourceState for a specific resource, or None if no
        eligible evidence exists.
        """
        facts = self._grouped.get((system_id, resource_id))
        if not facts:
            return None
        return self._build_state(system_id, resource_id, facts)

    def get_all_states(self, user_id: str) -> List[ResourceState]:
        """
        Return ResourceState for every resource that has at least one eligible
        evidence fact linked to the given user_id.
        """
        states: List[ResourceState] = []
        seen: Set[Tuple[str, str]] = set()
        for (sys_id, res_id), facts in self._grouped.items():
            key = (sys_id, res_id)
            if key in seen:
                continue
            # Filter to facts for this user_id
            user_facts = [f for f in facts if f.subject_user_id == user_id or not f.subject_user_id]
            if not user_facts:
                continue
            seen.add(key)
            state = self._build_state(sys_id, res_id, user_facts)
            if state:
                states.append(state)
        return states

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_state(
        self,
        system_id: str,
        resource_id: str,
        facts: List[EvidenceFact],
    ) -> Optional[ResourceState]:
        """
        Build a ResourceState from a list of facts (already sorted newest-first).
        Detect replica drift when facts from different snapshots conflict.
        """
        if not facts:
            return None

        best = facts[0]  # most recent eligible fact

        # Detect drift: if any other fact has a DIFFERENT state observed in the
        # same approximate time window (within 7 days), flag drift
        has_drift = False
        for f in facts[1:]:
            if f.observed_state != best.observed_state:
                # Only flag drift for facts within a week of the best evidence
                delta = abs((best.captured_at - f.captured_at).total_seconds())
                if delta < 7 * 86400:
                    has_drift = True
                    logger.debug(
                        "Replica drift for %s/%s: %s vs %s (files: %s, %s)",
                        system_id, resource_id,
                        best.observed_state, f.observed_state,
                        best.file_id, f.file_id,
                    )
                    break

        user_id = best.subject_user_id or ""
        data_cat = best.data_category

        return ResourceState(
            user_id=user_id,
            system_id=system_id,
            resource_id=resource_id,
            data_category=data_cat or _infer_category(system_id, resource_id),
            state_at_audit=best.observed_state,
            best_evidence_file_id=best.file_id,
            best_evidence_captured_at=best.captured_at,
            all_evidence_file_ids=list({f.file_id for f in facts}),
            has_replica_drift=has_drift,
            needs_review=best.needs_review or has_drift,
        )


def _infer_category(system_id: str, resource_id: str) -> DataCategory:
    """
    Fallback data category inference when the fact does not carry one.
    Based on system_id + resource_id prefix patterns from DATA_DISCOVERY.md §4.2.
    """
    rid_prefix = resource_id.split("_")[0] if "_" in resource_id else resource_id
    _MAP: Dict[str, DataCategory] = {
        # By resource_id prefix
        "account": DataCategory.USER_PROFILE,
        "search": DataCategory.SEARCH_INDEX_ENTRY,
        "analytics": DataCategory.ANALYTICS_PROFILE,
        "support": DataCategory.SUPPORT_MESSAGE,
        "export": DataCategory.USER_EXPORT,
        "data": DataCategory.USER_PROFILE,  # data_flow — overridden below
        "backup": DataCategory.BACKUP_ARCHIVE,
        "audit": DataCategory.SECURITY_AUDIT_LOG,
        "tombstone": DataCategory.ACCOUNT_TOMBSTONE,
        "marketing": DataCategory.MARKETING_PROFILE,
        "legal": DataCategory.LEGAL_HOLD_RECORD,
        "email": DataCategory.EMAIL_DELIVERY_LOG,
    }
    if resource_id.startswith("data_flow"):
        # integration_service data flows are not a standard DataCategory —
        # they are handled as DataFlowState
        return DataCategory.USER_PROFILE  # placeholder; will be overridden
    cat = _MAP.get(rid_prefix)
    if cat:
        return cat
    # Fall back to system_id
    _SYS_MAP: Dict[str, DataCategory] = {
        "account_service": DataCategory.USER_PROFILE,
        "search_service": DataCategory.SEARCH_INDEX_ENTRY,
        "analytics_platform": DataCategory.ANALYTICS_PROFILE,
        "support_platform": DataCategory.SUPPORT_MESSAGE,
        "export_service": DataCategory.USER_EXPORT,
        "backup_service": DataCategory.BACKUP_ARCHIVE,
        "security_service": DataCategory.SECURITY_AUDIT_LOG,
        "identity_service": DataCategory.ACCOUNT_TOMBSTONE,
        "marketing_platform": DataCategory.MARKETING_PROFILE,
        "legal_service": DataCategory.LEGAL_HOLD_RECORD,
    }
    return _SYS_MAP.get(system_id, DataCategory.USER_PROFILE)
