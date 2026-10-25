"""
audit_engine.py — Top-level orchestration for a single case audit.

Input contract:
    AuditEngine(config, identities, audit_log, deletion_rules, evidence_manifest,
                dataset_root)
    .audit_case(case: RequestCase) -> CaseResult

The engine coordinates:
  1. LLM request classification (is deletion authorized?)
  2. Identity resolution (email → user_id + all aliases)
  3. Evidence loading + EvidenceFact extraction
  4. Temporal reconstruction (state at audit_at)
  5. Policy evaluation (findings)
  6. Step building (findings + remediation + verification)
  7. CaseResult assembly
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .config import RunConfig
from .data_flows import extract_data_flows, extract_restore_risks
from .audit_core import ActivityEvent, TemporalEventProcessor
from .evidence import EvidenceLoader
from .identity import IdentityResolution, IdentityResolver
from .llm import LLMClient, RequestClassification
from .policy import PolicyEngine
from .schemas import (
    AuditFinding,
    CaseResult,
    DataCategory,
    DeletionStatus,
    EvidenceFact,
    LLMConfidence,
    PolicyRule,
    RecordState,
    RequestCase,
    ResourceState,
    RunUsage,
)
from .step_builder import build_steps
from .temporal import TemporalReconstructor

logger = logging.getLogger(__name__)


class AuditEngine:
    """
    Coordinates all modules to produce a CaseResult for a single deletion request.

    All expensive indexes (identities, audit_log, rules) are built once during
    __init__ and reused across all cases.
    """

    def __init__(
        self,
        config: RunConfig,
        identities: Dict[str, Dict],
        audit_log: List[Dict],
        deletion_rules: List[PolicyRule],
        evidence_manifest: List[Any],  # List[EvidenceRef]
        dataset_root: Any,             # Path
        activity_rows: Optional[List[Dict[str, str]]] = None,
    ) -> None:
        self._config = config
        self._activity_rows = activity_rows or []
        self._usage = RunUsage()
        self._identity_resolver = IdentityResolver(
            identities, audit_log, dataset_root=str(dataset_root)
        )
        self._policy_engine = PolicyEngine(deletion_rules)
        self._policy_rules: Dict[DataCategory, PolicyRule] = {
            r.data_category: r for r in deletion_rules
        }
        self._evidence_loader = EvidenceLoader(
            manifest=evidence_manifest,
            dataset_root=dataset_root,
            config=config,
            usage=self._usage,
        )
        self._llm_client = LLMClient(config.llm, usage=self._usage)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def audit_case(self, case: RequestCase) -> CaseResult:
        """Process a single deletion request and return a CaseResult."""
        logger.debug("Auditing %s (email=%s, audit_at=%s)",
                     case.case_id, case.email, case.audit_at.isoformat())

        result = CaseResult(case_id=case.case_id, deletion_status=DeletionStatus.INCOMPLETE)

        # --- Step 1: Classify request ---
        classification = self._classify(case)
        result.request_authorized = classification.authorized
        result.authorization_reason = classification.reason
        result.authorization_llm_confidence = classification.confidence

        if not classification.authorized:
            result.deletion_status = DeletionStatus.NOT_APPLICABLE
            result.steps = []
            return result

        # --- Step 2: Resolve identity ---
        resolution = self._identity_resolver.resolve(case.email, case.audit_at)
        if not resolution.found:
            logger.warning("[%s] No identity match for %s", case.case_id, case.email)
            # The request is still an explicit deletion request. Unknown or
            # ambiguous identity is an evidence gap, never authorization to
            # skip the audit.
            result.deletion_status = DeletionStatus.INCOMPLETE
            result.authorization_reason = "User identity could not be resolved; audit evidence is insufficient"
            result.needs_review = True
            result.steps = []
            return result

        result.user_id = resolution.user_id
        result.resolved_emails = resolution.all_emails

        # --- Step 3: Load evidence ---
        facts: List[EvidenceFact] = self._evidence_loader.load_facts_for_user(
            resolution, case.audit_at
        )
        result.evidence_file_ids_used = list({f.file_id for f in facts})
        logger.debug("[%s] Found %d evidence facts from %d files",
                     case.case_id, len(facts), len(result.evidence_file_ids_used))

        if not facts:
            # No eligible, linked evidence cannot prove absence, policy
            # treatment, flow safety, or restore safety.
            result.deletion_status = DeletionStatus.INCOMPLETE
            result.authorization_reason = "No eligible evidence was extracted; completeness cannot be established"
            result.needs_review = True
            result.steps = []
            return result

        # --- Step 4: Temporal reconstruction ---
        reconstructor = TemporalReconstructor(facts, case.audit_at)
        eligible_facts = [fact for fact in facts if fact.captured_at <= case.audit_at]
        resource_states: List[ResourceState] = reconstructor.get_all_states(
            resolution.user_id
        )

        # --- Step 5: Extract data flows and restore risks ---
        data_flows = extract_data_flows(eligible_facts, resolution.user_id)
        restore_risks = extract_restore_risks(eligible_facts, resolution.user_id)

        # Activity is claim evidence, not proof of record state. It is still
        # needed to detect the explicit sync-after-delete recreation pattern.
        events = self._activity_events_for_case(resolution, facts)
        temporal = TemporalEventProcessor(events, case.audit_at)
        state_by_resource = {
            state.resource_id: state for state in resource_states
        }
        for resource_id, state in state_by_resource.items():
            if state.state_at_audit.value != "ABSENT":
                continue
            sync_event = temporal.has_active_sync_after_deletion(resource_id)
            if sync_event is None:
                continue
            from .schemas import DataFlowState
            data_flows.append(DataFlowState(
                user_id=resolution.user_id,
                resource_id=f"sync_{resource_id}",
                connector_name=sync_event.source_system,
                subject_selector=None,
                enabled=True,
                best_evidence_file_id=sync_event.activity_id,
                best_evidence_captured_at=sync_event.event_time,
            ))

        # --- Step 6: Policy evaluation ---
        findings: List[AuditFinding] = self._policy_engine.evaluate(
            user_id=resolution.user_id,
            resource_states=resource_states,
            data_flows=data_flows,
            restore_risks=restore_risks,
        )
        result.findings = findings

        # --- Step 7: Determine deletion status ---
        if findings:
            result.deletion_status = DeletionStatus.INCOMPLETE
        else:
            result.deletion_status = DeletionStatus.COMPLETE

        if any(state.needs_review for state in resource_states):
            result.deletion_status = DeletionStatus.INCOMPLETE
            result.needs_review = True

        # --- Step 8: Build steps ---
        evidence_map = {
            rs.resource_id: rs.best_evidence_file_id for rs in resource_states
        }
        for df in data_flows:
            evidence_map[df.resource_id] = df.best_evidence_file_id
        for rr in restore_risks:
            evidence_map[rr.resource_id] = rr.best_evidence_file_id

        result.steps = build_steps(
            deletion_status=result.deletion_status,
            findings=findings,
            resource_states=resource_states,
            data_flows=data_flows,
            restore_risks=restore_risks,
            policy_rules=self._policy_rules,
            evidence_map=evidence_map,
        )

        # Flag for review if any evidence is LLM-derived with low confidence
        if any(f.needs_review for f in facts):
            result.needs_review = True

        return result

    def _activity_events_for_case(
        self, resolution: IdentityResolution, facts: List[EvidenceFact]
    ) -> List[ActivityEvent]:
        """Link global activity rows by grounded identifiers/resources."""
        identifiers = {value.casefold() for value in resolution.all_identifiers if value}
        resource_ids = {fact.resource_id for fact in facts if fact.resource_id}
        linked_rows: List[Dict[str, str]] = []
        for row in self._activity_rows:
            details = (row.get("details") or "").casefold()
            if row.get("resource_id") in resource_ids or any(i in details for i in identifiers):
                linked_rows.append(row)
                if row.get("resource_id"):
                    resource_ids.add(row["resource_id"])
        # A resource linked by a catalog event can then be followed through
        # subsequent activity rows, without treating unrelated global rows as
        # belonging to this subject.
        for row in self._activity_rows:
            if row.get("resource_id") in resource_ids and row not in linked_rows:
                linked_rows.append(row)
        events: List[ActivityEvent] = []
        from .schemas import _parse_utc
        for row in linked_rows:
            try:
                events.append(ActivityEvent(
                    activity_id=row["activity_id"],
                    event_time=_parse_utc(row["event_time"]),
                    event_type=row.get("event_type", ""),
                    source_system=row.get("source_system", ""),
                    target_system=row.get("target_system", ""),
                    resource_id=row.get("resource_id", ""),
                    reported_result=row.get("reported_result", ""),
                    details=row.get("details", ""),
                ))
            except (KeyError, ValueError):
                continue
        return events

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _classify(self, case: RequestCase) -> RequestClassification:
        """Classify the request text. Uses LLM if mode != 'off' and needed."""
        return self._llm_client.classify_request(
            case.request_text, case_id=case.case_id
        )

    @property
    def usage(self) -> RunUsage:
        return self._usage
