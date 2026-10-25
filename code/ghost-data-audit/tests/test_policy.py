"""
test_policy.py — Unit tests for policy.py.

Tests:
  - required_action for each of the 15 data categories
  - Conditional rules behave correctly with different context flags
  - evaluate() returns findings for resources in wrong state
  - evaluate() returns no findings when all resources are compliant
  - evaluate() reports active data flows
  - evaluate() reports restore risks
"""

import pytest
from datetime import datetime, timezone

from ghost_audit.policy import PolicyEngine
from ghost_audit.schemas import (
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


# ---------------------------------------------------------------------------
# Build a PolicyEngine from all 15 rules (matching deletion_rules.csv)
# ---------------------------------------------------------------------------

_RULES = [
    PolicyRule(rule_id="rule_01", data_category=DataCategory.USER_PROFILE, condition="Always", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_02", data_category=DataCategory.SECONDARY_IDENTIFIER, condition="Always", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_03", data_category=DataCategory.SEARCH_INDEX_ENTRY, condition="Always", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_04", data_category=DataCategory.CACHE_ENTRY, condition="Always", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_05", data_category=DataCategory.SUPPORT_MESSAGE, condition="Conversation contains shared context", required_action=RequiredAction.REDACT),
    PolicyRule(rule_id="rule_06", data_category=DataCategory.SUPPORT_ATTACHMENT, condition="Attachment belongs only to the deletion subject", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_07", data_category=DataCategory.ANALYTICS_PROFILE, condition="Record is still attributable to a user", required_action=RequiredAction.ANONYMIZE),
    PolicyRule(rule_id="rule_08", data_category=DataCategory.PRODUCT_TELEMETRY, condition="Record is still attributable to a user", required_action=RequiredAction.ANONYMIZE),
    PolicyRule(rule_id="rule_09", data_category=DataCategory.USER_EXPORT, condition="Always", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_10", data_category=DataCategory.MARKETING_PROFILE, condition="Always", required_action=RequiredAction.DELETE),
    PolicyRule(rule_id="rule_11", data_category=DataCategory.EMAIL_DELIVERY_LOG, condition="Log contains a user email address", required_action=RequiredAction.REDACT),
    PolicyRule(rule_id="rule_12", data_category=DataCategory.SECURITY_AUDIT_LOG, condition="Record is within the supplied retention period", required_action=RequiredAction.RETAIN),
    PolicyRule(rule_id="rule_13", data_category=DataCategory.LEGAL_HOLD_RECORD, condition="A supplied legal hold is active", required_action=RequiredAction.RETAIN),
    PolicyRule(rule_id="rule_14", data_category=DataCategory.BACKUP_ARCHIVE, condition="Restore access can be blocked", required_action=RequiredAction.RETAIN),
    PolicyRule(rule_id="rule_15", data_category=DataCategory.ACCOUNT_TOMBSTONE, condition="Account is deleted and only a stable internal user_id is needed", required_action=RequiredAction.REDACT),
]


@pytest.fixture
def engine():
    return PolicyEngine(_RULES)


def _make_resource(resource_id, system_id, data_category, state, evidence_id="evidence_01"):
    return ResourceState(
        user_id="user_01",
        system_id=system_id,
        resource_id=resource_id,
        data_category=data_category,
        state_at_audit=state,
        best_evidence_file_id=evidence_id,
        best_evidence_captured_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# required_action tests
# ---------------------------------------------------------------------------

class TestRequiredAction:
    @pytest.mark.parametrize("cat,expected", [
        (DataCategory.USER_PROFILE, RequiredAction.DELETE),
        (DataCategory.SECONDARY_IDENTIFIER, RequiredAction.DELETE),
        (DataCategory.SEARCH_INDEX_ENTRY, RequiredAction.DELETE),
        (DataCategory.CACHE_ENTRY, RequiredAction.DELETE),
        (DataCategory.USER_EXPORT, RequiredAction.DELETE),
        (DataCategory.MARKETING_PROFILE, RequiredAction.DELETE),
        (DataCategory.SUPPORT_MESSAGE, RequiredAction.REDACT),
        (DataCategory.ANALYTICS_PROFILE, RequiredAction.ANONYMIZE),
        (DataCategory.PRODUCT_TELEMETRY, RequiredAction.ANONYMIZE),
    ])
    def test_unconditional_actions(self, engine, cat, expected):
        action = engine.required_action(cat)
        assert action == expected

    def test_security_audit_within_retention_period(self, engine):
        action = engine.required_action(
            DataCategory.SECURITY_AUDIT_LOG,
            context={"within_retention_period": True}
        )
        assert action == RequiredAction.RETAIN

    def test_security_audit_past_retention(self, engine):
        action = engine.required_action(
            DataCategory.SECURITY_AUDIT_LOG,
            context={"within_retention_period": False}
        )
        assert action is None  # No action needed

    def test_legal_hold_active(self, engine):
        action = engine.required_action(
            DataCategory.LEGAL_HOLD_RECORD,
            context={"has_legal_hold": True}
        )
        assert action == RequiredAction.RETAIN

    def test_legal_hold_inactive(self, engine):
        action = engine.required_action(
            DataCategory.LEGAL_HOLD_RECORD,
            context={"has_legal_hold": False}
        )
        assert action is None

    def test_backup_blockable(self, engine):
        action = engine.required_action(
            DataCategory.BACKUP_ARCHIVE,
            context={"restore_blockable": True}
        )
        assert action == RequiredAction.RETAIN

    def test_analytics_attributable(self, engine):
        action = engine.required_action(
            DataCategory.ANALYTICS_PROFILE,
            context={"record_attributable": True}
        )
        assert action == RequiredAction.ANONYMIZE

    def test_analytics_already_anonymized(self, engine):
        action = engine.required_action(
            DataCategory.ANALYTICS_PROFILE,
            context={"record_attributable": False}
        )
        assert action is None

    def test_tombstone_account_deleted(self, engine):
        action = engine.required_action(
            DataCategory.ACCOUNT_TOMBSTONE,
            context={"account_deleted": True}
        )
        assert action == RequiredAction.REDACT


# ---------------------------------------------------------------------------
# evaluate() tests
# ---------------------------------------------------------------------------

class TestEvaluate:
    def test_no_findings_when_all_compliant(self, engine):
        resources = [
            _make_resource("account_001", "account_service", DataCategory.USER_PROFILE, RecordState.ABSENT),
            _make_resource("search_001", "search_service", DataCategory.SEARCH_INDEX_ENTRY, RecordState.ABSENT),
            _make_resource("audit_record_001", "security_service", DataCategory.SECURITY_AUDIT_LOG, RecordState.PRESENT),
        ]
        findings = engine.evaluate("user_01", resources, [], [])
        assert findings == []

    def test_finding_for_remaining_user_profile(self, engine):
        resources = [
            _make_resource("account_001", "account_service", DataCategory.USER_PROFILE, RecordState.PRESENT),
        ]
        findings = engine.evaluate("user_01", resources, [], [])
        assert len(findings) == 1
        f = findings[0]
        assert f.operation == Operation.REPORT_REMAINING_RECORD
        assert f.state == RecordState.PRESENT
        assert f.resource_id == "account_001"

    def test_finding_for_identifiable_analytics(self, engine):
        resources = [
            _make_resource("analytics_001", "analytics_platform", DataCategory.ANALYTICS_PROFILE, RecordState.PRESENT),
        ]
        findings = engine.evaluate("user_01", resources, [], [])
        assert len(findings) == 1
        assert findings[0].operation == Operation.REPORT_EXPOSED_PII

    def test_no_finding_for_anonymized_analytics(self, engine):
        resources = [
            _make_resource("analytics_001", "analytics_platform", DataCategory.ANALYTICS_PROFILE, RecordState.ANONYMIZED),
        ]
        findings = engine.evaluate("user_01", resources, [], [])
        assert findings == []

    def test_finding_for_active_data_flow(self, engine):
        data_flows = [
            DataFlowState(
                user_id="user_01",
                resource_id="data_flow_001",
                enabled=True,
                best_evidence_file_id="evidence_01",
                best_evidence_captured_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
            )
        ]
        findings = engine.evaluate("user_01", [], data_flows, [])
        assert len(findings) == 1
        assert findings[0].operation == Operation.REPORT_ACTIVE_DATA_FLOW
        assert findings[0].state == RecordState.ACTIVE

    def test_no_finding_for_disabled_data_flow(self, engine):
        data_flows = [
            DataFlowState(
                user_id="user_01",
                resource_id="data_flow_001",
                enabled=False,
                best_evidence_file_id="evidence_01",
                best_evidence_captured_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
            )
        ]
        findings = engine.evaluate("user_01", [], data_flows, [])
        assert findings == []

    def test_finding_for_restore_risk(self, engine):
        restore_risks = [
            RestoreRisk(
                user_id="user_01",
                resource_id="backup_001",
                restore_allowed=True,
                best_evidence_file_id="evidence_01",
                best_evidence_captured_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
            )
        ]
        findings = engine.evaluate("user_01", [], [], restore_risks)
        assert len(findings) == 1
        assert findings[0].operation == Operation.REPORT_RESTORE_RISK

    def test_no_finding_for_blocked_restore(self, engine):
        restore_risks = [
            RestoreRisk(
                user_id="user_01",
                resource_id="backup_001",
                restore_allowed=False,
                best_evidence_file_id="evidence_01",
                best_evidence_captured_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
            )
        ]
        findings = engine.evaluate("user_01", [], [], restore_risks)
        assert findings == []

    def test_multiple_findings_returned(self, engine):
        resources = [
            _make_resource("account_001", "account_service", DataCategory.USER_PROFILE, RecordState.PRESENT),
            _make_resource("search_001", "search_service", DataCategory.SEARCH_INDEX_ENTRY, RecordState.PRESENT),
            _make_resource("analytics_001", "analytics_platform", DataCategory.ANALYTICS_PROFILE, RecordState.PRESENT),
        ]
        findings = engine.evaluate("user_01", resources, [], [])
        assert len(findings) == 3
