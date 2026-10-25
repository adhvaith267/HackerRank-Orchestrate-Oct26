"""
policy.py — Policy evaluation engine.

Input contract:
    PolicyEngine(rules: List[PolicyRule])
    .required_action(data_category, context) -> RequiredAction
    .evaluate(resource_states, data_flows, restore_risks) -> List[AuditFinding]

All 15 rules from deletion_rules.csv are encoded here.
Context dict carries the keys needed to evaluate conditional rules
(e.g. 'has_legal_hold', 'attachment_belongs_to_subject').
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .schemas import (
    AuditFinding,
    DataCategory,
    DataFlowState,
    Operation,
    PolicyRule,
    RecordState,
    RequiredAction,
    ResourceState,
    RestoreRisk,
)

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Evaluates deletion policy for a set of resource states and returns
    the list of AuditFindings (policy violations).

    Parameters
    ----------
    rules:
        List[PolicyRule] loaded from deletion_rules.csv.
        Stored by data_category for O(1) lookup.
    """

    def __init__(self, rules: List[PolicyRule]) -> None:
        self._rules: Dict[DataCategory, PolicyRule] = {}
        for rule in rules:
            self._rules[rule.data_category] = rule

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def required_action(
        self,
        data_category: DataCategory,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[RequiredAction]:
        """
        Look up the required action for a data category.

        For conditional rules (SUPPORT_MESSAGE, ANALYTICS_PROFILE, etc.),
        the context dict provides the condition flags.

        Context keys:
          'has_legal_hold' (bool)           — rule_13
          'restore_blockable' (bool)         — rule_14
          'within_retention_period' (bool)  — rule_12
          'attachment_belongs_to_subject' (bool) — rule_06
          'record_attributable' (bool)      — rule_07, rule_08
          'log_has_email' (bool)            — rule_11
          'account_deleted' (bool)          — rule_15
        """
        rule = self._rules.get(data_category)
        if rule is None:
            logger.warning("No policy rule for data_category=%s", data_category)
            return None
        ctx = context or {}

        # Conditional rule evaluation
        if data_category == DataCategory.SECURITY_AUDIT_LOG:
            if not ctx.get("within_retention_period", True):
                return None  # No action needed if past retention
            return RequiredAction.RETAIN

        if data_category == DataCategory.LEGAL_HOLD_RECORD:
            if not ctx.get("has_legal_hold", True):
                return None
            return RequiredAction.RETAIN

        if data_category == DataCategory.BACKUP_ARCHIVE:
            if ctx.get("restore_blockable", True):
                return RequiredAction.RETAIN  # retain but block restore
            return None

        if data_category == DataCategory.SUPPORT_ATTACHMENT:
            if ctx.get("attachment_belongs_to_subject", True):
                return RequiredAction.DELETE
            return RequiredAction.REDACT  # shared context → redact

        if data_category == DataCategory.ANALYTICS_PROFILE:
            if ctx.get("record_attributable", True):
                return RequiredAction.ANONYMIZE
            return None  # Already anonymized

        if data_category == DataCategory.PRODUCT_TELEMETRY:
            if ctx.get("record_attributable", True):
                return RequiredAction.ANONYMIZE
            return None

        if data_category == DataCategory.EMAIL_DELIVERY_LOG:
            if ctx.get("log_has_email", True):
                return RequiredAction.REDACT
            return None

        if data_category == DataCategory.ACCOUNT_TOMBSTONE:
            if ctx.get("account_deleted", True):
                return RequiredAction.REDACT
            return None

        return rule.required_action

    def evaluate(
        self,
        user_id: str,
        resource_states: List[ResourceState],
        data_flows: List[DataFlowState],
        restore_risks: List[RestoreRisk],
        context_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[AuditFinding]:
        """
        Evaluate all resource states against policy rules and return findings.

        Parameters
        ----------
        user_id: str
        resource_states: List[ResourceState]
            Each resource's observed state at audit_at.
        data_flows: List[DataFlowState]
            Active integration connectors for this user.
        restore_risks: List[RestoreRisk]
            Backup archives that can restore the user's data.
        context_overrides: Optional dict mapping resource_id → context dict
            for conditional rule evaluation.

        Returns
        -------
        List[AuditFinding]
            Policy violations found; empty if deletion is complete.
        """
        findings: List[AuditFinding] = []
        overrides = context_overrides or {}

        # --- Evaluate regular resource states ---
        for rs in resource_states:
            ctx = overrides.get(rs.resource_id, {})
            action = self.required_action(rs.data_category, ctx)
            if action is None:
                continue  # No action required for this resource

            finding = self._check_resource(user_id, rs, action)
            if finding:
                findings.append(finding)

        # --- Evaluate active data flows ---
        for df in data_flows:
            if df.enabled:
                findings.append(AuditFinding(
                    user_id=user_id,
                    system_id="integration_service",
                    resource_id=df.resource_id,
                    data_category=DataCategory.USER_PROFILE,  # placeholder
                    operation=Operation.REPORT_ACTIVE_DATA_FLOW,
                    state=RecordState.ACTIVE,
                    evidence_file_id=df.best_evidence_file_id,
                    description=f"Active data flow {df.resource_id} can recreate user data",
                ))

        # --- Evaluate restore risks ---
        for rr in restore_risks:
            if rr.restore_allowed:
                findings.append(AuditFinding(
                    user_id=user_id,
                    system_id="backup_service",
                    resource_id=rr.resource_id,
                    data_category=DataCategory.BACKUP_ARCHIVE,
                    operation=Operation.REPORT_RESTORE_RISK,
                    state=RecordState.ACTIVE,
                    evidence_file_id=rr.best_evidence_file_id,
                    description=f"Backup {rr.resource_id} can restore deleted data",
                ))

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_resource(
        self,
        user_id: str,
        rs: ResourceState,
        action: RequiredAction,
    ) -> Optional[AuditFinding]:
        """
        Compare the observed state with the required final state.
        Return an AuditFinding if there is a violation, else None.
        """
        # Map required_action → expected final RecordState
        _ACTION_TO_FINAL_STATE: Dict[RequiredAction, RecordState] = {
            RequiredAction.DELETE: RecordState.ABSENT,
            RequiredAction.REDACT: RecordState.REDACTED,
            RequiredAction.ANONYMIZE: RecordState.ANONYMIZED,
            RequiredAction.RETAIN: RecordState.PRESENT,
        }
        expected_state = _ACTION_TO_FINAL_STATE[action]

        # Already in the required state → no finding
        if rs.state_at_audit == expected_state:
            return None

        # Special: RETAIN means the record MUST exist — if absent, that is also
        # a policy violation (though extremely rare in practice)
        if action == RequiredAction.RETAIN:
            if rs.state_at_audit != RecordState.PRESENT:
                return AuditFinding(
                    user_id=user_id,
                    system_id=rs.system_id,
                    resource_id=rs.resource_id,
                    data_category=rs.data_category,
                    operation=Operation.REPORT_REMAINING_RECORD,
                    state=RecordState.PRESENT,
                    evidence_file_id=rs.best_evidence_file_id,
                    description=f"Policy requires RETAIN but record is {rs.state_at_audit}",
                )
            return None

        # DELETE required — record still present
        if action == RequiredAction.DELETE and rs.state_at_audit == RecordState.PRESENT:
            return AuditFinding(
                user_id=user_id,
                system_id=rs.system_id,
                resource_id=rs.resource_id,
                data_category=rs.data_category,
                operation=Operation.REPORT_REMAINING_RECORD,
                state=RecordState.PRESENT,
                evidence_file_id=rs.best_evidence_file_id,
                description=f"Record should be deleted but is still PRESENT",
            )

        # REDACT required — PII still exposed (record is PRESENT but not REDACTED)
        if action == RequiredAction.REDACT and rs.state_at_audit not in (
            RecordState.REDACTED, RecordState.ABSENT
        ):
            return AuditFinding(
                user_id=user_id,
                system_id=rs.system_id,
                resource_id=rs.resource_id,
                data_category=rs.data_category,
                operation=Operation.REPORT_EXPOSED_PII,
                state=RecordState.PRESENT,
                evidence_file_id=rs.best_evidence_file_id,
                description=f"PII identifiers should be redacted but record state is {rs.state_at_audit}",
            )

        # ANONYMIZE required — record still identifiable
        if action == RequiredAction.ANONYMIZE and rs.state_at_audit not in (
            RecordState.ANONYMIZED, RecordState.ABSENT
        ):
            return AuditFinding(
                user_id=user_id,
                system_id=rs.system_id,
                resource_id=rs.resource_id,
                data_category=rs.data_category,
                operation=Operation.REPORT_EXPOSED_PII,
                state=RecordState.PRESENT,
                evidence_file_id=rs.best_evidence_file_id,
                description=f"Record should be anonymized but state is {rs.state_at_audit}",
            )

        return None
