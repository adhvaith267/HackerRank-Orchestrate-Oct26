"""
step_builder.py — Build ordered AuditStep lists from findings and planned actions.

Input contract:
    build_steps(
        findings: List[AuditFinding],
        resource_states: List[ResourceState],
        data_flows: List[DataFlowState],
        restore_risks: List[RestoreRisk],
        deletion_status: DeletionStatus,
        evidence_map: Dict[str, str],  # resource_id -> best evidence_file_id
    ) -> List[AuditStep]

Ordering rules (canonical source: AGENTS.md §6.4 operation tables +
sample_output.csv verification via DATA_DISCOVERY.md §5.3):

FINDING phase order:
  1. REPORT_REMAINING_RECORD
  2. REPORT_EXPOSED_PII
  3. REPORT_ACTIVE_DATA_FLOW
  4. REPORT_RESTORE_RISK
  Within each: alphabetical by system_id, then resource_id.

REMEDIATION phase order:
  1. DISABLE_DATA_FLOW
  2. BLOCK_RESTORE
  3. DELETE_RECORD
  4. REDACT_RECORD
  5. ANONYMIZE_RECORD
  Within each: alphabetical by system_id, then resource_id.

VERIFICATION phase order:
  1. VERIFY_RECORD_ABSENT       (sorted by system_id, resource_id)
  2. VERIFY_RECORD_PRESENT      (sorted by system_id, resource_id)
  3. VERIFY_RECORD_REDACTED     (sorted by system_id, resource_id)
  4. VERIFY_RECORD_ANONYMIZED   (sorted by system_id, resource_id)
  5. VERIFY_DATA_FLOW_DISABLED  (sorted by system_id, resource_id)
  6. VERIFY_RESTORE_BLOCKED     (sorted by system_id, resource_id)

NOTE: The FINDING order above is sourced from AGENTS.md §6.4 table
(REPORT_REMAINING_RECORD first) and confirmed by sample_output.csv case_11
and case_18. An earlier draft of this file had REPORT_ACTIVE_DATA_FLOW first,
which contradicted the canonical spec; that draft order has been corrected.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from .schemas import (
    AuditFinding,
    AuditStep,
    DataCategory,
    DataFlowState,
    DeletionStatus,
    Operation,
    Phase,
    PlannedAction,
    PolicyRule,
    RecordState,
    RequiredAction,
    ResourceState,
    RestoreRisk,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ordering keys
# ---------------------------------------------------------------------------

_FINDING_OP_ORDER: Dict[Operation, int] = {
    # Canonical order from AGENTS.md §6.4 table and confirmed by sample_output.csv
    # case_11 and case_18: REMAINING_RECORD first, EXPOSED_PII second,
    # ACTIVE_DATA_FLOW third, RESTORE_RISK fourth.
    Operation.REPORT_REMAINING_RECORD: 0,
    Operation.REPORT_EXPOSED_PII: 1,
    Operation.REPORT_ACTIVE_DATA_FLOW: 2,
    Operation.REPORT_RESTORE_RISK: 3,
}

_REMEDIATION_OP_ORDER: Dict[Operation, int] = {
    Operation.DISABLE_DATA_FLOW: 0,
    Operation.BLOCK_RESTORE: 1,
    Operation.DELETE_RECORD: 2,
    Operation.REDACT_RECORD: 3,
    Operation.ANONYMIZE_RECORD: 4,
}

_VERIFICATION_OP_ORDER: Dict[Operation, int] = {
    Operation.VERIFY_RECORD_ABSENT: 0,
    Operation.VERIFY_RECORD_PRESENT: 1,
    Operation.VERIFY_RECORD_REDACTED: 2,
    Operation.VERIFY_RECORD_ANONYMIZED: 3,
    Operation.VERIFY_DATA_FLOW_DISABLED: 4,
    Operation.VERIFY_RESTORE_BLOCKED: 5,
}


def _finding_sort_key(f: AuditFinding) -> Tuple:
    return (_FINDING_OP_ORDER.get(f.operation, 99), f.system_id, f.resource_id)


def _remediation_sort_key(a: PlannedAction) -> Tuple:
    return (_REMEDIATION_OP_ORDER.get(a.operation, 99), a.system_id, a.resource_id)


def _verification_sort_key(a: PlannedAction) -> Tuple:
    return (_VERIFICATION_OP_ORDER.get(a.operation, 99), a.system_id, a.resource_id)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_steps(
    deletion_status: DeletionStatus,
    findings: List[AuditFinding],
    resource_states: List[ResourceState],
    data_flows: List[DataFlowState],
    restore_risks: List[RestoreRisk],
    policy_rules: Dict[DataCategory, PolicyRule],
    evidence_map: Optional[Dict[str, str]] = None,
) -> List[AuditStep]:
    """
    Assemble the complete ordered steps_json for a case.

    Parameters
    ----------
    deletion_status:
        COMPLETE → only verification steps (with evidence_id)
        INCOMPLETE → finding + remediation + verification steps
        NOT_APPLICABLE → empty list
    findings:
        AuditFinding objects (finding-phase steps)
    resource_states:
        All resource states at audit_at for this user
    data_flows:
        DataFlowState objects for this user
    restore_risks:
        RestoreRisk objects for this user
    policy_rules:
        Dict[DataCategory, PolicyRule] for required_action lookups
    evidence_map:
        Dict mapping resource_id → file_id for COMPLETE verification evidence
    """
    if deletion_status == DeletionStatus.NOT_APPLICABLE:
        return []

    evidence_map = evidence_map or {}

    if deletion_status == DeletionStatus.COMPLETE:
        return _build_complete_steps(
            resource_states, data_flows, restore_risks, policy_rules, evidence_map
        )
    else:
        return _build_incomplete_steps(
            findings, resource_states, data_flows, restore_risks, policy_rules
        )


# ---------------------------------------------------------------------------
# COMPLETE path: verification only
# ---------------------------------------------------------------------------

def _build_complete_steps(
    resource_states: List[ResourceState],
    data_flows: List[DataFlowState],
    restore_risks: List[RestoreRisk],
    policy_rules: Dict[DataCategory, PolicyRule],
    evidence_map: Dict[str, str],
) -> List[AuditStep]:
    """
    For COMPLETE cases: one verification step per resource confirming
    its compliant final state. Each step cites the evidence_id.
    """
    actions: List[PlannedAction] = []

    for rs in resource_states:
        rule = policy_rules.get(rs.data_category)
        if rule is None:
            continue
        op = _verify_op_for_action(rule.required_action, rs.state_at_audit)
        if op is None:
            continue
        ev_id = evidence_map.get(rs.resource_id) or rs.best_evidence_file_id
        actions.append(PlannedAction(
            phase=Phase.VERIFICATION,
            system_id=rs.system_id,
            resource_id=rs.resource_id,
            operation=op,
            state=rs.state_at_audit,
            evidence_id=ev_id,
        ))

    for df in data_flows:
        if not df.enabled:  # disabled = compliant
            actions.append(PlannedAction(
                phase=Phase.VERIFICATION,
                system_id="integration_service",
                resource_id=df.resource_id,
                operation=Operation.VERIFY_DATA_FLOW_DISABLED,
                state=RecordState.DISABLED,
                evidence_id=evidence_map.get(df.resource_id) or df.best_evidence_file_id,
            ))

    for rr in restore_risks:
        if not rr.restore_allowed:  # blocked = compliant
            actions.append(PlannedAction(
                phase=Phase.VERIFICATION,
                system_id="backup_service",
                resource_id=rr.resource_id,
                operation=Operation.VERIFY_RESTORE_BLOCKED,
                state=RecordState.BLOCKED,
                evidence_id=evidence_map.get(rr.resource_id) or rr.best_evidence_file_id,
            ))

    return _number_steps(sorted(actions, key=_verification_sort_key), start=1)


# ---------------------------------------------------------------------------
# INCOMPLETE path: findings + remediation + verification
# ---------------------------------------------------------------------------

def _build_incomplete_steps(
    findings: List[AuditFinding],
    resource_states: List[ResourceState],
    data_flows: List[DataFlowState],
    restore_risks: List[RestoreRisk],
    policy_rules: Dict[DataCategory, PolicyRule],
) -> List[AuditStep]:
    """Build finding + remediation + verification steps for an INCOMPLETE case."""

    # Build finding steps — AuditFindings are converted directly to AuditSteps
    # (not PlannedActions, because PlannedAction rejects phase=FINDING by design)
    sorted_findings = sorted(findings, key=_finding_sort_key)
    finding_audit_steps: List[AuditStep] = []
    for i, f in enumerate(sorted_findings, start=1):
        finding_audit_steps.append(AuditStep(
            step_no=i,  # temporary; renumbered at the end
            phase=Phase.FINDING,
            system_id=f.system_id,
            resource_id=f.resource_id,
            operation=f.operation,
            state=f.state,
            evidence_id=f.evidence_file_id,
        ))

    # Build remediation steps (one per finding, in remediation order)
    remediation_steps: List[PlannedAction] = []
    for f in sorted_findings:
        op = _remediation_op_for_finding(f.operation, f.data_category, policy_rules)
        if op is None:
            continue
        target_state = _target_state_for_remediation(op)
        remediation_steps.append(PlannedAction(
            phase=Phase.REMEDIATION,
            system_id=f.system_id,
            resource_id=f.resource_id,
            operation=op,
            state=target_state,
            evidence_id="",
        ))
    remediation_steps.sort(key=_remediation_sort_key)

    # Build verification steps (cover all resources — remediated + already compliant)
    verification_steps: List[PlannedAction] = _build_incomplete_verification(
        findings, resource_states, data_flows, restore_risks, policy_rules
    )

    # Combine: finding AuditSteps first, then remediation and verification PlannedActions
    # Convert remediation and verification PlannedActions to AuditSteps with placeholder step_no
    rem_ver_audit_steps = _number_steps(remediation_steps + verification_steps, start=1)

    # Merge all and renumber sequentially
    all_steps = finding_audit_steps + rem_ver_audit_steps
    return _renumber_steps(all_steps)


def _build_incomplete_verification(
    findings: List[AuditFinding],
    resource_states: List[ResourceState],
    data_flows: List[DataFlowState],
    restore_risks: List[RestoreRisk],
    policy_rules: Dict[DataCategory, PolicyRule],
) -> List[PlannedAction]:
    """Build future verification steps for an INCOMPLETE case (all evidence_id='')."""
    actions: List[PlannedAction] = []
    seen: Set[Tuple[str, str]] = set()

    # Resources that were found in findings
    finding_resources: Dict[Tuple[str, str], AuditFinding] = {
        (f.system_id, f.resource_id): f for f in findings
    }

    # All resource states
    for rs in resource_states:
        key = (rs.system_id, rs.resource_id)
        if key in seen:
            continue
        seen.add(key)
        rule = policy_rules.get(rs.data_category)
        if rule is None:
            continue
        # Determine the target state after remediation
        finding = finding_resources.get(key)
        if finding:
            op = _remediation_op_for_finding(finding.operation, rs.data_category, policy_rules)
            target_state = _target_state_for_remediation(op) if op else None
        else:
            target_state = _final_state_for_action(rule.required_action)

        if target_state is None:
            continue
        verify_op = _verify_op_for_state(target_state)
        if verify_op is None:
            continue
        actions.append(PlannedAction(
            phase=Phase.VERIFICATION,
            system_id=rs.system_id,
            resource_id=rs.resource_id,
            operation=verify_op,
            state=target_state,
            evidence_id="",
        ))

    # Data flows
    for df in data_flows:
        key = ("integration_service", df.resource_id)
        if key in seen:
            continue
        seen.add(key)
        actions.append(PlannedAction(
            phase=Phase.VERIFICATION,
            system_id="integration_service",
            resource_id=df.resource_id,
            operation=Operation.VERIFY_DATA_FLOW_DISABLED,
            state=RecordState.DISABLED,
            evidence_id="",
        ))

    # Restore risks
    for rr in restore_risks:
        key = ("backup_service", rr.resource_id)
        if key in seen:
            continue
        seen.add(key)
        actions.append(PlannedAction(
            phase=Phase.VERIFICATION,
            system_id="backup_service",
            resource_id=rr.resource_id,
            operation=Operation.VERIFY_RESTORE_BLOCKED,
            state=RecordState.BLOCKED,
            evidence_id="",
        ))

    return sorted(actions, key=_verification_sort_key)


# ---------------------------------------------------------------------------
# Helper lookups
# ---------------------------------------------------------------------------

def _verify_op_for_action(
    action: RequiredAction, current_state: RecordState
) -> Optional[Operation]:
    """Map a required_action to the verification operation for COMPLETE cases."""
    _MAP = {
        RequiredAction.DELETE: Operation.VERIFY_RECORD_ABSENT,
        RequiredAction.REDACT: Operation.VERIFY_RECORD_REDACTED,
        RequiredAction.ANONYMIZE: Operation.VERIFY_RECORD_ANONYMIZED,
        RequiredAction.RETAIN: Operation.VERIFY_RECORD_PRESENT,
    }
    return _MAP.get(action)


def _verify_op_for_state(state: RecordState) -> Optional[Operation]:
    _MAP = {
        RecordState.ABSENT: Operation.VERIFY_RECORD_ABSENT,
        RecordState.REDACTED: Operation.VERIFY_RECORD_REDACTED,
        RecordState.ANONYMIZED: Operation.VERIFY_RECORD_ANONYMIZED,
        RecordState.PRESENT: Operation.VERIFY_RECORD_PRESENT,
        RecordState.DISABLED: Operation.VERIFY_DATA_FLOW_DISABLED,
        RecordState.BLOCKED: Operation.VERIFY_RESTORE_BLOCKED,
    }
    return _MAP.get(state)


def _remediation_op_for_finding(
    finding_op: Operation,
    data_category: DataCategory,
    policy_rules: Dict[DataCategory, PolicyRule],
) -> Optional[Operation]:
    """Map a finding operation to its corresponding remediation operation."""
    if finding_op == Operation.REPORT_ACTIVE_DATA_FLOW:
        return Operation.DISABLE_DATA_FLOW
    if finding_op == Operation.REPORT_RESTORE_RISK:
        return Operation.BLOCK_RESTORE
    # For REPORT_REMAINING_RECORD / REPORT_EXPOSED_PII, use the policy action
    rule = policy_rules.get(data_category)
    if rule is None:
        return Operation.DELETE_RECORD
    _ACTION_OP_MAP = {
        RequiredAction.DELETE: Operation.DELETE_RECORD,
        RequiredAction.REDACT: Operation.REDACT_RECORD,
        RequiredAction.ANONYMIZE: Operation.ANONYMIZE_RECORD,
        RequiredAction.RETAIN: None,  # RETAIN findings don't have remediation
    }
    return _ACTION_OP_MAP.get(rule.required_action)


def _target_state_for_remediation(op: Optional[Operation]) -> RecordState:
    """Return the target RecordState after a remediation operation."""
    if op is None:
        return RecordState.ABSENT
    _MAP = {
        Operation.DISABLE_DATA_FLOW: RecordState.DISABLED,
        Operation.BLOCK_RESTORE: RecordState.BLOCKED,
        Operation.DELETE_RECORD: RecordState.ABSENT,
        Operation.REDACT_RECORD: RecordState.REDACTED,
        Operation.ANONYMIZE_RECORD: RecordState.ANONYMIZED,
    }
    return _MAP.get(op, RecordState.ABSENT)


def _final_state_for_action(action: RequiredAction) -> Optional[RecordState]:
    _MAP = {
        RequiredAction.DELETE: RecordState.ABSENT,
        RequiredAction.REDACT: RecordState.REDACTED,
        RequiredAction.ANONYMIZE: RecordState.ANONYMIZED,
        RequiredAction.RETAIN: RecordState.PRESENT,
    }
    return _MAP.get(action)


def _number_steps(actions: List[PlannedAction], start: int = 1) -> List[AuditStep]:
    """Convert PlannedActions to numbered AuditSteps."""
    steps: List[AuditStep] = []
    for i, action in enumerate(actions, start=start):
        steps.append(AuditStep(
            step_no=i,
            phase=action.phase,
            system_id=action.system_id,
            resource_id=action.resource_id,
            operation=action.operation,
            state=action.state,
            evidence_id=action.evidence_id,
        ))
    return steps


def _renumber_steps(steps: List[AuditStep]) -> List[AuditStep]:
    """Return a new list of AuditSteps with consecutive step_no starting from 1."""
    renumbered: List[AuditStep] = []
    for i, step in enumerate(steps, start=1):
        if step.step_no == i:
            renumbered.append(step)
        else:
            renumbered.append(AuditStep(
                step_no=i,
                phase=step.phase,
                system_id=step.system_id,
                resource_id=step.resource_id,
                operation=step.operation,
                state=step.state,
                evidence_id=step.evidence_id,
            ))
    return renumbered
