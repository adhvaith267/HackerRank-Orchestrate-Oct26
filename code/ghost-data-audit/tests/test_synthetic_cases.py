"""
test_synthetic_cases.py — End-to-end synthetic case tests.

These tests exercise the full pipeline (identity → evidence → policy → steps)
using minimal synthetic data. They do NOT use the actual dataset files.

Synthetic cases:
  1. Simple COMPLETE case — account absent, analytics anonymized, security retained
  2. Simple INCOMPLETE case — account still present → DELETE + verify
  3. NOT_APPLICABLE — request_text is an access request
  4. INCOMPLETE with active data flow — DISABLE + verify
  5. INCOMPLETE with restore risk — BLOCK + verify
  6. COMPLETE with tombstone — identity_service tombstone redacted
"""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path

from ghost_audit.config import RunConfig, LLMConfig, DatasetConfig, OutputConfig
from ghost_audit.identity import IdentityResolver
from ghost_audit.policy import PolicyEngine
from ghost_audit.schemas import (
    AuditFinding,
    AuditStep,
    CaseResult,
    DataCategory,
    DataFlowState,
    DeletionStatus,
    EvidenceFact,
    LLMConfidence,
    Operation,
    Phase,
    PolicyRule,
    RecordState,
    RequestCase,
    RequiredAction,
    ResourceState,
    RestoreRisk,
)
from ghost_audit.step_builder import build_steps
from ghost_audit.temporal import TemporalReconstructor


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_RULES = [
    PolicyRule(rule_id="rule_01", data_category=DataCategory.USER_PROFILE, condition="Always", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_03", data_category=DataCategory.SEARCH_INDEX_ENTRY, condition="Always", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_07", data_category=DataCategory.ANALYTICS_PROFILE, condition="Record is still attributable to a user", required_action=RequiredAction.ANONYMIZE),
    PolicyRule(rule_id="rule_12", data_category=DataCategory.SECURITY_AUDIT_LOG, condition="Record is within the supplied retention period", required_action=RequiredAction.RETAIN),
    PolicyRule(rule_id="rule_14", data_category=DataCategory.BACKUP_ARCHIVE, condition="Restore access can be blocked", required_action=RequiredAction.RETAIN),
    PolicyRule(rule_id="rule_15", data_category=DataCategory.ACCOUNT_TOMBSTONE, condition="Account deleted", required_action=RequiredAction.REDACT),
]

_POLICY_RULES_DICT = {r.data_category: r for r in _RULES}

AUDIT_AT = datetime(2026, 9, 20, tzinfo=timezone.utc)
EVIDENCE_TS = datetime(2026, 9, 15, tzinfo=timezone.utc)


def _rs(resource_id, system_id, cat, state, evidence_id="evidence_01"):
    return ResourceState(
        user_id="user_01",
        system_id=system_id,
        resource_id=resource_id,
        data_category=cat,
        state_at_audit=state,
        best_evidence_file_id=evidence_id,
        best_evidence_captured_at=EVIDENCE_TS,
    )


@pytest.fixture
def policy_engine():
    return PolicyEngine(_RULES)


# ---------------------------------------------------------------------------
# Case 1: COMPLETE — account absent, analytics anonymized, audit retained
# ---------------------------------------------------------------------------

class TestCase1Complete:
    def test_no_findings(self, policy_engine):
        resources = [
            _rs("account_001", "account_service", DataCategory.USER_PROFILE, RecordState.ABSENT),
            _rs("analytics_001", "analytics_platform", DataCategory.ANALYTICS_PROFILE, RecordState.ANONYMIZED),
            _rs("audit_record_001", "security_service", DataCategory.SECURITY_AUDIT_LOG, RecordState.PRESENT),
        ]
        findings = policy_engine.evaluate("user_01", resources, [], [])
        assert findings == []

    def test_builds_verification_steps_only(self, policy_engine):
        resources = [
            _rs("account_001", "account_service", DataCategory.USER_PROFILE, RecordState.ABSENT, "evidence_54"),
            _rs("analytics_001", "analytics_platform", DataCategory.ANALYTICS_PROFILE, RecordState.ANONYMIZED, "evidence_54"),
            _rs("audit_record_001", "security_service", DataCategory.SECURITY_AUDIT_LOG, RecordState.PRESENT, "evidence_54"),
        ]
        evidence_map = {r.resource_id: r.best_evidence_file_id for r in resources}
        steps = build_steps(
            deletion_status=DeletionStatus.COMPLETE,
            findings=[],
            resource_states=resources,
            data_flows=[],
            restore_risks=[],
            policy_rules=_POLICY_RULES_DICT,
            evidence_map=evidence_map,
        )
        phases = {s.phase for s in steps}
        assert phases == {Phase.VERIFICATION}
        ops = {s.operation for s in steps}
        assert Operation.VERIFY_RECORD_ABSENT in ops
        assert Operation.VERIFY_RECORD_ANONYMIZED in ops
        assert Operation.VERIFY_RECORD_PRESENT in ops

    def test_all_verification_steps_have_evidence_id(self):
        resources = [
            _rs("account_001", "account_service", DataCategory.USER_PROFILE, RecordState.ABSENT, "evidence_54"),
        ]
        evidence_map = {"account_001": "evidence_54"}
        steps = build_steps(
            deletion_status=DeletionStatus.COMPLETE,
            findings=[],
            resource_states=resources,
            data_flows=[],
            restore_risks=[],
            policy_rules=_POLICY_RULES_DICT,
            evidence_map=evidence_map,
        )
        for step in steps:
            assert step.evidence_id != "", f"COMPLETE step has empty evidence_id: {step}"

    def test_step_nos_sequential(self):
        resources = [
            _rs("account_001", "account_service", DataCategory.USER_PROFILE, RecordState.ABSENT, "evidence_54"),
            _rs("audit_record_001", "security_service", DataCategory.SECURITY_AUDIT_LOG, RecordState.PRESENT, "evidence_54"),
        ]
        evidence_map = {r.resource_id: r.best_evidence_file_id for r in resources}
        steps = build_steps(
            deletion_status=DeletionStatus.COMPLETE,
            findings=[],
            resource_states=resources,
            data_flows=[],
            restore_risks=[],
            policy_rules=_POLICY_RULES_DICT,
            evidence_map=evidence_map,
        )
        for i, step in enumerate(steps, start=1):
            assert step.step_no == i


# ---------------------------------------------------------------------------
# Case 2: INCOMPLETE — account still present
# ---------------------------------------------------------------------------

class TestCase2Incomplete:
    def test_finding_for_present_account(self, policy_engine):
        resources = [
            _rs("account_002", "account_service", DataCategory.USER_PROFILE, RecordState.PRESENT),
        ]
        findings = policy_engine.evaluate("user_01", resources, [], [])
        assert len(findings) == 1
        assert findings[0].operation == Operation.REPORT_REMAINING_RECORD
        assert findings[0].resource_id == "account_002"

    def test_builds_finding_remediation_verification(self, policy_engine):
        resources = [
            _rs("account_002", "account_service", DataCategory.USER_PROFILE, RecordState.PRESENT, "evidence_05"),
        ]
        findings = policy_engine.evaluate("user_01", resources, [], [])
        steps = build_steps(
            deletion_status=DeletionStatus.INCOMPLETE,
            findings=findings,
            resource_states=resources,
            data_flows=[],
            restore_risks=[],
            policy_rules=_POLICY_RULES_DICT,
        )
        phases_in_order = [s.phase for s in steps]
        assert phases_in_order[0] == Phase.FINDING
        ops = [s.operation for s in steps]
        assert Operation.REPORT_REMAINING_RECORD in ops
        assert Operation.DELETE_RECORD in ops
        assert Operation.VERIFY_RECORD_ABSENT in ops

    def test_remediation_steps_have_empty_evidence_id(self, policy_engine):
        resources = [
            _rs("account_002", "account_service", DataCategory.USER_PROFILE, RecordState.PRESENT, "evidence_05"),
        ]
        findings = policy_engine.evaluate("user_01", resources, [], [])
        steps = build_steps(
            deletion_status=DeletionStatus.INCOMPLETE,
            findings=findings,
            resource_states=resources,
            data_flows=[],
            restore_risks=[],
            policy_rules=_POLICY_RULES_DICT,
        )
        remediation_steps = [s for s in steps if s.phase == Phase.REMEDIATION]
        for s in remediation_steps:
            assert s.evidence_id == "", f"Remediation step has non-empty evidence_id: {s}"


# ---------------------------------------------------------------------------
# Case 3: NOT_APPLICABLE
# ---------------------------------------------------------------------------

class TestCase3NotApplicable:
    def test_not_applicable_has_empty_steps(self):
        steps = build_steps(
            deletion_status=DeletionStatus.NOT_APPLICABLE,
            findings=[],
            resource_states=[],
            data_flows=[],
            restore_risks=[],
            policy_rules=_POLICY_RULES_DICT,
        )
        assert steps == []

    def test_llm_classify_access_request_returns_not_authorized(self):
        from ghost_audit.llm import _classify_by_rules
        result = _classify_by_rules("I would like to download a copy of all my data.")
        assert result is not None
        assert result.authorized is False

    def test_llm_classify_deletion_request_authorized(self):
        from ghost_audit.llm import _classify_by_rules
        result = _classify_by_rules("Please delete my account and all personal data.")
        assert result is not None
        assert result.authorized is True

    def test_llm_classify_multilingual_spanish(self):
        from ghost_audit.llm import _classify_by_rules
        result = _classify_by_rules("Por favor, elimina mi cuenta y todos mis datos personales.")
        assert result is not None
        assert result.authorized is True


# ---------------------------------------------------------------------------
# Case 4: INCOMPLETE with active data flow
# ---------------------------------------------------------------------------

class TestCase4DataFlow:
    def test_active_flow_generates_finding(self, policy_engine):
        data_flows = [
            DataFlowState(
                user_id="user_01",
                resource_id="data_flow_9846",
                enabled=True,
                best_evidence_file_id="evidence_14",
                best_evidence_captured_at=EVIDENCE_TS,
            )
        ]
        findings = policy_engine.evaluate("user_01", [], data_flows, [])
        assert len(findings) == 1
        assert findings[0].operation == Operation.REPORT_ACTIVE_DATA_FLOW
        assert findings[0].resource_id == "data_flow_9846"

    def test_data_flow_step_order(self, policy_engine):
        """DISABLE_DATA_FLOW must come before DELETE_RECORD in remediation."""
        resources = [
            _rs("account_004", "account_service", DataCategory.USER_PROFILE, RecordState.PRESENT, "evidence_14"),
        ]
        data_flows = [
            DataFlowState(
                user_id="user_01",
                resource_id="data_flow_9846",
                enabled=True,
                best_evidence_file_id="evidence_14",
                best_evidence_captured_at=EVIDENCE_TS,
            )
        ]
        findings = policy_engine.evaluate("user_01", resources, data_flows, [])
        steps = build_steps(
            deletion_status=DeletionStatus.INCOMPLETE,
            findings=findings,
            resource_states=resources,
            data_flows=data_flows,
            restore_risks=[],
            policy_rules=_POLICY_RULES_DICT,
        )
        remediation_steps = [s for s in steps if s.phase == Phase.REMEDIATION]
        op_order = [s.operation for s in remediation_steps]
        disable_idx = op_order.index(Operation.DISABLE_DATA_FLOW) if Operation.DISABLE_DATA_FLOW in op_order else -1
        delete_idx = op_order.index(Operation.DELETE_RECORD) if Operation.DELETE_RECORD in op_order else -1
        if disable_idx >= 0 and delete_idx >= 0:
            assert disable_idx < delete_idx, "DISABLE_DATA_FLOW must precede DELETE_RECORD"


# ---------------------------------------------------------------------------
# Case 5: INCOMPLETE with restore risk
# ---------------------------------------------------------------------------

class TestCase5RestoreRisk:
    def test_restore_risk_finding(self, policy_engine):
        restore_risks = [
            RestoreRisk(
                user_id="user_01",
                resource_id="backup_4978",
                restore_allowed=True,
                best_evidence_file_id="evidence_93",
                best_evidence_captured_at=EVIDENCE_TS,
            )
        ]
        findings = policy_engine.evaluate("user_01", [], [], restore_risks)
        assert len(findings) == 1
        assert findings[0].operation == Operation.REPORT_RESTORE_RISK
        assert findings[0].state == RecordState.ACTIVE

    def test_block_restore_in_remediation(self, policy_engine):
        restore_risks = [
            RestoreRisk(
                user_id="user_01",
                resource_id="backup_4978",
                restore_allowed=True,
                best_evidence_file_id="evidence_93",
                best_evidence_captured_at=EVIDENCE_TS,
            )
        ]
        findings = policy_engine.evaluate("user_01", [], [], restore_risks)
        steps = build_steps(
            deletion_status=DeletionStatus.INCOMPLETE,
            findings=findings,
            resource_states=[],
            data_flows=[],
            restore_risks=restore_risks,
            policy_rules=_POLICY_RULES_DICT,
        )
        ops = [s.operation for s in steps]
        assert Operation.BLOCK_RESTORE in ops
        assert Operation.VERIFY_RESTORE_BLOCKED in ops


# ---------------------------------------------------------------------------
# Case 6: COMPLETE with tombstone
# ---------------------------------------------------------------------------

class TestCase6Tombstone:
    def test_tombstone_redacted_no_finding(self, policy_engine):
        resources = [
            _rs("tombstone_440", "identity_service", DataCategory.ACCOUNT_TOMBSTONE, RecordState.REDACTED),
            _rs("audit_record_6909", "security_service", DataCategory.SECURITY_AUDIT_LOG, RecordState.PRESENT),
        ]
        findings = policy_engine.evaluate("user_01", resources, [], [])
        assert findings == []

    def test_tombstone_not_redacted_generates_finding(self, policy_engine):
        resources = [
            _rs("tombstone_9178", "identity_service", DataCategory.ACCOUNT_TOMBSTONE, RecordState.PRESENT),
        ]
        findings = policy_engine.evaluate("user_01", resources, [], [])
        assert len(findings) == 1
        assert findings[0].operation == Operation.REPORT_EXPOSED_PII
        assert findings[0].resource_id == "tombstone_9178"

    def test_tombstone_remediation_is_redact(self, policy_engine):
        resources = [
            _rs("tombstone_9178", "identity_service", DataCategory.ACCOUNT_TOMBSTONE, RecordState.PRESENT, "evidence_51"),
        ]
        findings = policy_engine.evaluate("user_01", resources, [], [])
        steps = build_steps(
            deletion_status=DeletionStatus.INCOMPLETE,
            findings=findings,
            resource_states=resources,
            data_flows=[],
            restore_risks=[],
            policy_rules=_POLICY_RULES_DICT,
        )
        remediation_steps = [s for s in steps if s.phase == Phase.REMEDIATION]
        assert len(remediation_steps) >= 1
        assert Operation.REDACT_RECORD in [s.operation for s in remediation_steps]
