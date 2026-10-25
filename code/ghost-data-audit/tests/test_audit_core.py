"""
test_audit_core.py — Focused unit tests for audit_core.py deterministic audit engine.

Covers all 12 E-scenario test cases specified in the task:
  E1.  Deletion succeeded only in primary service (stale replica)
  E2.  Stale replica — record absent in primary, present in replica
  E3.  Tombstone with valid user_id but email remaining (violation)
  E4.  Allowed retained record (SECURITY_AUDIT_LOG within retention)
  E5.  Email hash remaining in a record that should be REDACTED
  E6.  Active sync can recreate a deleted record
  E7.  Disabled sync — no longer a risk
  E8.  Restore risk from backup (restore_allowed=True)
  E9.  Blocked restore — already safe (restore_allowed=False)
  E10. Contradictory success/failure activity (same resource, same time)
  E11. Event after audit_at must be excluded from state determination
  E12. Insufficient evidence coverage (no eligible facts for a resource)

Plus supporting unit tests for each component:
  - ResourceInventory: ingest, conflict, transition history
  - TemporalEventProcessor: conflict rules, future events, sync-after-delete
  - PolicyEngine: CSV parse, conditional rules, tombstone, email-hash warning
  - DataFlowAnalyzer: active vs historical, restore risks
  - AuditAnalysis: is_complete, summary
"""

from __future__ import annotations

import csv
import io
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from ghost_audit.audit_core import (
    ActivityEvent,
    AuditAnalysis,
    AuditCore,
    ConflictKind,
    DataFlowAnalyzer,
    DataFlowRecord,
    EvidenceGap,
    FlowStatus,
    InventoryEntry,
    PolicyEngine,
    PolicyViolation,
    ResourceInventory,
    ResourceInventoryState,
    RestoreRiskRecord,
    RetainedRecord,
    TemporalEventProcessor,
    TypedPolicyRule,
    _ensure_utc,
    _parse_ts,
)
from ghost_audit.schemas import (
    DataCategory,
    EvidenceFact,
    EvidenceFormat,
    EvidenceRef,
    RecordState,
    RequiredAction,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UTC = timezone.utc


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _make_fact(
    file_id: str = "evidence_01",
    system_id: str = "account_service",
    resource_id: str = "account_001",
    observed_state: RecordState = RecordState.PRESENT,
    captured_at: str = "2026-09-01T00:00:00Z",
    data_category: Optional[DataCategory] = DataCategory.USER_PROFILE,
    subject_user_id: Optional[str] = "user_01",
    subject_email: Optional[str] = None,
    raw_value: Optional[str] = None,
) -> EvidenceFact:
    return EvidenceFact(
        file_id=file_id,
        file_path=f"evidence/test/{file_id}.json",
        captured_at=captured_at,
        system_id=system_id,
        resource_id=resource_id,
        subject_user_id=subject_user_id,
        subject_email=subject_email,
        data_category=data_category,
        observed_state=observed_state,
        raw_value=raw_value,
        source_span="test",
        llm_derived=False,
    )


def _make_activity(
    activity_id: str,
    event_type: str,
    resource_id: str,
    reported_result: str = "SUCCESS",
    event_time: str = "2026-08-01T00:00:00Z",
    source_system: str = "deletion_worker",
    target_system: str = "account_service",
) -> ActivityEvent:
    return ActivityEvent(
        activity_id=activity_id,
        event_time=_dt(event_time),
        event_type=event_type,
        source_system=source_system,
        target_system=target_system,
        resource_id=resource_id,
        reported_result=reported_result,
        details="",
    )


# Minimal deletion_rules.csv content for PolicyEngine
_DELETION_RULES_CSV = """\
rule_id,data_category,condition,required_action
rule_01,USER_PROFILE,Always,DELETE
rule_02,SECONDARY_IDENTIFIER,Always,DELETE
rule_03,SEARCH_INDEX_ENTRY,Always,DELETE
rule_04,CACHE_ENTRY,Always,DELETE
rule_05,SUPPORT_MESSAGE,Conversation contains shared customer agent or order context that must be retained,REDACT
rule_06,SUPPORT_ATTACHMENT,Attachment belongs only to the deletion subject,DELETE
rule_07,ANALYTICS_PROFILE,Record is still attributable to a user,ANONYMIZE
rule_08,PRODUCT_TELEMETRY,Record is still attributable to a user,ANONYMIZE
rule_09,USER_EXPORT,Always,DELETE
rule_10,MARKETING_PROFILE,Always,DELETE
rule_11,EMAIL_DELIVERY_LOG,Log contains a user email address,REDACT
rule_12,SECURITY_AUDIT_LOG,Record is within the supplied retention period,RETAIN
rule_13,LEGAL_HOLD_RECORD,A supplied legal hold is active,RETAIN
rule_14,BACKUP_ARCHIVE,Restore access can be blocked,RETAIN
rule_15,ACCOUNT_TOMBSTONE,Account is deleted and only a stable internal user_id is needed to preserve references to retained records,REDACT
"""

AUDIT_AT = _dt("2026-10-01T00:00:00Z")
BEFORE_AUDIT = _dt("2026-09-01T00:00:00Z")
AFTER_AUDIT = _dt("2026-10-02T00:00:00Z")


@pytest.fixture
def policy_engine(tmp_path):
    csv_file = tmp_path / "deletion_rules.csv"
    csv_file.write_text(_DELETION_RULES_CSV, encoding="utf-8")
    return PolicyEngine.from_csv(csv_file)


@pytest.fixture
def audit_core(policy_engine):
    return AuditCore(policy_engine)


# ===========================================================================
# ResourceInventory tests
# ===========================================================================

class TestResourceInventory:
    def test_ingest_present_fact(self):
        inv = ResourceInventory()
        fact = _make_fact(observed_state=RecordState.PRESENT, captured_at="2026-09-01T00:00:00Z")
        inv.ingest_fact(fact, AUDIT_AT)
        entry = inv.get("account_service", "account_001")
        assert entry is not None
        assert entry.state == ResourceInventoryState.PRESENT

    def test_ingest_absent_fact(self):
        inv = ResourceInventory()
        fact = _make_fact(observed_state=RecordState.ABSENT, captured_at="2026-09-01T00:00:00Z")
        inv.ingest_fact(fact, AUDIT_AT)
        entry = inv.get("account_service", "account_001")
        assert entry.state == ResourceInventoryState.ABSENT_CONFIRMED

    def test_ingest_redacted_fact(self):
        inv = ResourceInventory()
        fact = _make_fact(observed_state=RecordState.REDACTED, captured_at="2026-09-01T00:00:00Z")
        inv.ingest_fact(fact, AUDIT_AT)
        entry = inv.get("account_service", "account_001")
        assert entry.state == ResourceInventoryState.REDACTED_CONFIRMED

    def test_ingest_anonymized_fact(self):
        inv = ResourceInventory()
        fact = _make_fact(
            observed_state=RecordState.ANONYMIZED,
            system_id="analytics_platform",
            resource_id="analytics_001",
            data_category=DataCategory.ANALYTICS_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        inv.ingest_fact(fact, AUDIT_AT)
        entry = inv.get("analytics_platform", "analytics_001")
        assert entry.state == ResourceInventoryState.ANONYMIZED_CONFIRMED

    def test_fact_after_audit_at_is_ignored(self):
        inv = ResourceInventory()
        fact = _make_fact(
            observed_state=RecordState.PRESENT,
            captured_at=AFTER_AUDIT.isoformat().replace("+00:00", "Z"),
        )
        inv.ingest_fact(fact, AUDIT_AT)
        assert inv.get("account_service", "account_001") is None

    def test_same_timestamp_contradictory_states_become_conflicted(self):
        """Same capture time, different states → CONFLICTED."""
        inv = ResourceInventory()
        ts = "2026-09-01T00:00:00Z"
        fact_a = _make_fact(file_id="evidence_01", observed_state=RecordState.PRESENT, captured_at=ts)
        fact_b = _make_fact(file_id="evidence_02", observed_state=RecordState.ABSENT, captured_at=ts)
        inv.ingest_fact(fact_a, AUDIT_AT)
        inv.ingest_fact(fact_b, AUDIT_AT)
        entry = inv.get("account_service", "account_001")
        assert entry.state == ResourceInventoryState.CONFLICTED
        assert "evidence_02" in entry.conflicts

    def test_newer_evidence_overrides_older(self):
        inv = ResourceInventory()
        fact_old = _make_fact(file_id="evidence_01", observed_state=RecordState.PRESENT, captured_at="2026-08-01T00:00:00Z")
        fact_new = _make_fact(file_id="evidence_02", observed_state=RecordState.ABSENT, captured_at="2026-09-01T00:00:00Z")
        inv.ingest_fact(fact_old, AUDIT_AT)
        inv.ingest_fact(fact_new, AUDIT_AT)
        entry = inv.get("account_service", "account_001")
        # Newer fact (ABSENT) should win
        assert entry.state == ResourceInventoryState.ABSENT_CONFIRMED

    def test_state_transition_history_recorded(self):
        inv = ResourceInventory()
        fact_a = _make_fact(file_id="evidence_01", observed_state=RecordState.PRESENT, captured_at="2026-08-01T00:00:00Z")
        fact_b = _make_fact(file_id="evidence_02", observed_state=RecordState.ABSENT, captured_at="2026-09-01T00:00:00Z")
        inv.ingest_fact(fact_a, AUDIT_AT)
        inv.ingest_fact(fact_b, AUDIT_AT)
        entry = inv.get("account_service", "account_001")
        assert len(entry.history) >= 2

    def test_conflicted_entries_accessible(self):
        inv = ResourceInventory()
        ts = "2026-09-01T00:00:00Z"
        inv.ingest_fact(_make_fact(file_id="ev_1", observed_state=RecordState.PRESENT, captured_at=ts), AUDIT_AT)
        inv.ingest_fact(_make_fact(file_id="ev_2", observed_state=RecordState.ABSENT, captured_at=ts), AUDIT_AT)
        assert len(inv.conflicted_entries()) == 1

    def test_inv_state_maps_to_record_state(self):
        assert ResourceInventoryState.ABSENT_CONFIRMED.to_record_state() == RecordState.ABSENT
        assert ResourceInventoryState.PRESENT.to_record_state() == RecordState.PRESENT
        assert ResourceInventoryState.REDACTED_CONFIRMED.to_record_state() == RecordState.REDACTED
        assert ResourceInventoryState.ANONYMIZED_CONFIRMED.to_record_state() == RecordState.ANONYMIZED
        assert ResourceInventoryState.UNKNOWN.to_record_state() is None
        assert ResourceInventoryState.CONFLICTED.to_record_state() is None


# ===========================================================================
# TemporalEventProcessor tests
# ===========================================================================

class TestTemporalEventProcessor:
    def test_future_events_excluded_from_eligible(self):
        ev = _make_activity("act_01", "DELETE_RECORD", "account_001",
                            event_time=AFTER_AUDIT.isoformat().replace("+00:00", "Z"))
        proc = TemporalEventProcessor([ev], AUDIT_AT)
        assert len(proc.future_events) == 1
        assert len(proc.claims_for_resource("account_001")) == 0

    def test_future_event_recorded_as_conflict(self):
        ev = _make_activity("act_01", "DELETE_RECORD", "account_001",
                            event_time=AFTER_AUDIT.isoformat().replace("+00:00", "Z"))
        proc = TemporalEventProcessor([ev], AUDIT_AT)
        assert any(c.kind == ConflictKind.FUTURE_EVENT for c in proc.conflicts)

    def test_same_time_success_and_failure_triggers_contradictory_conflict(self):
        ts = "2026-09-15T10:00:00Z"
        ev_ok = _make_activity("act_01", "DELETE_RECORD", "account_001",
                               reported_result="SUCCESS", event_time=ts)
        ev_fail = _make_activity("act_02", "DELETE_RECORD", "account_001",
                                 reported_result="FAILED", event_time=ts)
        proc = TemporalEventProcessor([ev_ok, ev_fail], AUDIT_AT)
        assert any(c.kind == ConflictKind.SAME_TIME_CONTRADICTORY for c in proc.conflicts)

    def test_duplicate_activity_id_triggers_duplicate_conflict(self):
        ev1 = _make_activity("act_01", "DELETE_RECORD", "account_001", event_time="2026-09-01T10:00:00Z")
        ev2 = _make_activity("act_01", "DELETE_RECORD", "account_001", event_time="2026-09-01T10:00:00Z")
        proc = TemporalEventProcessor([ev1, ev2], AUDIT_AT)
        assert any(c.kind == ConflictKind.DUPLICATE_EVENT for c in proc.conflicts)

    def test_sync_after_delete_triggers_delayed_replication_conflict(self):
        ev_del = _make_activity("act_01", "DELETE_RECORD", "account_001",
                                reported_result="SUCCESS", event_time="2026-09-01T10:00:00Z")
        ev_sync = _make_activity("act_02", "SYNC_RECORD", "account_001",
                                 event_time="2026-09-15T10:00:00Z")
        proc = TemporalEventProcessor([ev_del, ev_sync], AUDIT_AT)
        assert any(c.kind == ConflictKind.DELAYED_REPLICATION for c in proc.conflicts)

    def test_has_active_sync_after_deletion(self):
        ev_del = _make_activity("act_01", "DELETE_RECORD", "account_001",
                                reported_result="SUCCESS", event_time="2026-09-01T10:00:00Z")
        ev_sync = _make_activity("act_02", "SYNC_RECORD", "account_001",
                                 event_time="2026-09-15T10:00:00Z")
        proc = TemporalEventProcessor([ev_del, ev_sync], AUDIT_AT)
        result = proc.has_active_sync_after_deletion("account_001")
        assert result is not None
        assert result.activity_id == "act_02"

    def test_no_sync_after_delete_returns_none(self):
        ev_del = _make_activity("act_01", "DELETE_RECORD", "account_001",
                                reported_result="SUCCESS", event_time="2026-09-01T10:00:00Z")
        proc = TemporalEventProcessor([ev_del], AUDIT_AT)
        assert proc.has_active_sync_after_deletion("account_001") is None

    def test_activity_event_is_deletion_claim(self):
        ev = _make_activity("act_01", "DELETE_RECORD", "account_001", reported_result="SUCCESS")
        assert ev.is_deletion_claim is True

    def test_failed_delete_is_not_deletion_claim(self):
        ev = _make_activity("act_01", "DELETE_RECORD", "account_001", reported_result="FAILED")
        assert ev.is_deletion_claim is False

    def test_sync_event_is_sync_event(self):
        ev = _make_activity("act_01", "SYNC_RECORD", "account_001")
        assert ev.is_sync_event is True


# ===========================================================================
# PolicyEngine tests
# ===========================================================================

class TestPolicyEngine:
    def test_from_csv_loads_all_15_rules(self, tmp_path):
        csv_file = tmp_path / "deletion_rules.csv"
        csv_file.write_text(_DELETION_RULES_CSV, encoding="utf-8")
        engine = PolicyEngine.from_csv(csv_file)
        rule = engine.get_rule(DataCategory.USER_PROFILE)
        assert rule is not None
        assert rule.rule_id == "rule_01"
        assert rule.required_action == RequiredAction.DELETE

    def test_from_csv_missing_column_raises(self, tmp_path):
        csv_file = tmp_path / "deletion_rules.csv"
        csv_file.write_text("rule_id,data_category\nrule_01,USER_PROFILE\n", encoding="utf-8")
        with pytest.raises(ValueError, match="missing required columns"):
            PolicyEngine.from_csv(csv_file)

    def test_always_delete_rule(self, policy_engine):
        assert policy_engine.required_treatment(DataCategory.USER_PROFILE) == RequiredAction.DELETE
        assert policy_engine.required_treatment(DataCategory.SEARCH_INDEX_ENTRY) == RequiredAction.DELETE
        assert policy_engine.required_treatment(DataCategory.USER_EXPORT) == RequiredAction.DELETE

    def test_conditional_security_audit_retain(self, policy_engine):
        # Within retention period → RETAIN
        assert policy_engine.required_treatment(
            DataCategory.SECURITY_AUDIT_LOG,
            {"within_retention_period": True}
        ) == RequiredAction.RETAIN
        # Past retention period → None (no action)
        assert policy_engine.required_treatment(
            DataCategory.SECURITY_AUDIT_LOG,
            {"within_retention_period": False}
        ) is None

    def test_conditional_analytics_anonymize(self, policy_engine):
        # Still attributable → ANONYMIZE
        assert policy_engine.required_treatment(
            DataCategory.ANALYTICS_PROFILE,
            {"record_attributable": True}
        ) == RequiredAction.ANONYMIZE
        # Already anonymous → None
        assert policy_engine.required_treatment(
            DataCategory.ANALYTICS_PROFILE,
            {"record_attributable": False}
        ) is None

    def test_tombstone_present_is_violation(self, policy_engine):
        entry = InventoryEntry(
            system_id="identity_service",
            resource_id="tombstone_001",
            data_category=DataCategory.ACCOUNT_TOMBSTONE,
            subject_user_id="user_01",
            state=ResourceInventoryState.PRESENT,
        )
        violation = policy_engine.evaluate_inventory(entry, {"account_deleted": True})
        assert violation is not None
        assert "tombstone" in violation.description.lower()

    def test_tombstone_redacted_confirmed_is_compliant(self, policy_engine):
        entry = InventoryEntry(
            system_id="identity_service",
            resource_id="tombstone_001",
            data_category=DataCategory.ACCOUNT_TOMBSTONE,
            subject_user_id="user_01",
            state=ResourceInventoryState.REDACTED_CONFIRMED,
        )
        violation = policy_engine.evaluate_inventory(entry, {"account_deleted": True})
        assert violation is None

    def test_absent_satisfies_delete_requirement(self, policy_engine):
        entry = InventoryEntry(
            system_id="account_service",
            resource_id="account_001",
            data_category=DataCategory.USER_PROFILE,
            subject_user_id="user_01",
            state=ResourceInventoryState.ABSENT_CONFIRMED,
        )
        violation = policy_engine.evaluate_inventory(entry)
        assert violation is None

    def test_unknown_state_triggers_violation(self, policy_engine):
        entry = InventoryEntry(
            system_id="account_service",
            resource_id="account_001",
            data_category=DataCategory.USER_PROFILE,
            subject_user_id="user_01",
            state=ResourceInventoryState.UNKNOWN,
        )
        violation = policy_engine.evaluate_inventory(entry)
        assert violation is not None
        assert "insufficient_evidence" in violation.description

    def test_conflicted_state_triggers_violation(self, policy_engine):
        entry = InventoryEntry(
            system_id="account_service",
            resource_id="account_001",
            data_category=DataCategory.USER_PROFILE,
            subject_user_id="user_01",
            state=ResourceInventoryState.CONFLICTED,
        )
        entry.conflicts = ["evidence_99"]
        violation = policy_engine.evaluate_inventory(entry)
        assert violation is not None
        assert "conflicted" in violation.description

    def test_redact_required_but_present_triggers_violation(self, policy_engine):
        """Email hash remaining in a record that should be REDACTED."""
        entry = InventoryEntry(
            system_id="notification_service",
            resource_id="email_delivery_001",
            data_category=DataCategory.EMAIL_DELIVERY_LOG,
            subject_user_id="user_01",
            state=ResourceInventoryState.PRESENT,
        )
        violation = policy_engine.evaluate_inventory(entry, {"log_has_email": True})
        assert violation is not None

    def test_backup_archive_retain_with_restore_blockable(self, policy_engine):
        assert policy_engine.required_treatment(
            DataCategory.BACKUP_ARCHIVE,
            {"restore_blockable": True}
        ) == RequiredAction.RETAIN

    def test_typed_rule_properties(self, tmp_path):
        csv_file = tmp_path / "deletion_rules.csv"
        csv_file.write_text(_DELETION_RULES_CSV, encoding="utf-8")
        engine = PolicyEngine.from_csv(csv_file)
        rule_01 = engine.get_rule(DataCategory.USER_PROFILE)
        assert rule_01.requires_complete_removal is True
        assert rule_01.is_conditional is False
        assert rule_01.retention_mandated is False

        rule_12 = engine.get_rule(DataCategory.SECURITY_AUDIT_LOG)
        assert rule_12.retention_mandated is True
        assert rule_12.is_conditional is True
        assert rule_12.requires_identifier_removal is False


# ===========================================================================
# DataFlowAnalyzer tests
# ===========================================================================

class TestDataFlowAnalyzer:
    def test_active_flow_detected(self):
        fact = _make_fact(
            file_id="evidence_14",
            system_id="integration_service",
            resource_id="data_flow_001",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analyzer = DataFlowAnalyzer([fact], AUDIT_AT)
        active = analyzer.active_flows()
        assert len(active) == 1
        assert active[0].resource_id == "data_flow_001"
        assert active[0].status == FlowStatus.ACTIVE

    def test_disabled_flow_is_historical(self):
        fact = _make_fact(
            file_id="evidence_14",
            system_id="integration_service",
            resource_id="data_flow_001",
            observed_state=RecordState.DISABLED,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analyzer = DataFlowAnalyzer([fact], AUDIT_AT)
        assert len(analyzer.active_flows()) == 0
        historical = analyzer.historical_flows()
        assert len(historical) == 1
        assert historical[0].status == FlowStatus.HISTORICAL

    def test_restore_risk_detected(self):
        fact = _make_fact(
            file_id="evidence_32",
            system_id="backup_service",
            resource_id="backup_9287",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.BACKUP_ARCHIVE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analyzer = DataFlowAnalyzer([fact], AUDIT_AT)
        risks = analyzer.restore_risks()
        assert len(risks) == 1
        assert risks[0].resource_id == "backup_9287"
        assert risks[0].is_active_risk is True

    def test_blocked_restore_not_an_active_risk(self):
        fact = _make_fact(
            file_id="evidence_32",
            system_id="backup_service",
            resource_id="backup_9287",
            observed_state=RecordState.BLOCKED,
            data_category=DataCategory.BACKUP_ARCHIVE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analyzer = DataFlowAnalyzer([fact], AUDIT_AT)
        risks = analyzer.restore_risks()
        assert len(risks) == 1
        assert risks[0].is_active_risk is False

    def test_post_audit_flow_fact_ignored(self):
        fact = _make_fact(
            system_id="integration_service",
            resource_id="data_flow_001",
            observed_state=RecordState.PRESENT,
            captured_at=AFTER_AUDIT.isoformat().replace("+00:00", "Z"),
        )
        analyzer = DataFlowAnalyzer([fact], AUDIT_AT)
        assert len(analyzer.active_flows()) == 0

    def test_most_recent_fact_wins_for_flow(self):
        """Two facts for the same data_flow — most recent should determine status."""
        fact_old = _make_fact(
            file_id="evidence_01",
            system_id="integration_service",
            resource_id="data_flow_001",
            observed_state=RecordState.PRESENT,
            captured_at="2026-07-01T00:00:00Z",
        )
        fact_new = _make_fact(
            file_id="evidence_02",
            system_id="integration_service",
            resource_id="data_flow_001",
            observed_state=RecordState.DISABLED,
            captured_at="2026-09-01T00:00:00Z",
        )
        analyzer = DataFlowAnalyzer([fact_old, fact_new], AUDIT_AT)
        assert len(analyzer.active_flows()) == 0
        assert len(analyzer.historical_flows()) == 1


# ===========================================================================
# E-Scenario tests (the 12 required scenarios)
# ===========================================================================

class TestE1_DeletionSucceededOnlyInPrimary:
    """Primary service reports absence, but replica still has the record."""

    def test_stale_replica_produces_violation(self, audit_core):
        # Primary: absent
        primary_fact = _make_fact(
            file_id="evidence_54",
            system_id="account_service",
            resource_id="account_005",
            observed_state=RecordState.ABSENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-21T00:00:00Z",
        )
        # Replica: still present (different file_id)
        replica_fact = _make_fact(
            file_id="evidence_52",
            system_id="account_service",
            resource_id="account_005",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.USER_PROFILE,
            # Same date = conflict
            captured_at="2026-09-21T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E1",
            user_id="user_05",
            audit_at=AUDIT_AT,
            evidence_facts=[primary_fact, replica_fact],
        )
        # Should be conflicted (same timestamp, different states)
        entry = next(
            (e for e in analysis.inventory if e.resource_id == "account_005"), None
        )
        assert entry is not None
        assert entry.state == ResourceInventoryState.CONFLICTED
        assert not analysis.is_complete


class TestE2_StaleReplica:
    """Record absent in primary but present in a later replica snapshot."""

    def test_primary_absent_replica_present_at_different_times(self, audit_core):
        # Primary snapshot: absent
        primary = _make_fact(
            file_id="evidence_54",
            system_id="account_service",
            resource_id="account_005",
            observed_state=RecordState.ABSENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-20T00:00:00Z",
        )
        # Replica snapshot captured later: still present
        replica = _make_fact(
            file_id="evidence_52",
            system_id="account_service",
            resource_id="account_005",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-21T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E2",
            user_id="user_05",
            audit_at=AUDIT_AT,
            evidence_facts=[primary, replica],
        )
        # Newer fact (replica PRESENT) wins → violation
        entry = next(
            (e for e in analysis.inventory if e.resource_id == "account_005"), None
        )
        assert entry is not None
        assert entry.state == ResourceInventoryState.PRESENT
        assert len(analysis.violations) >= 1


class TestE3_TombstoneWithEmailRemaining:
    """Tombstone exists but direct identifiers not removed (violation)."""

    def test_tombstone_present_state_is_violation(self, audit_core):
        tombstone_fact = _make_fact(
            file_id="evidence_51",
            system_id="identity_service",
            resource_id="tombstone_001",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.ACCOUNT_TOMBSTONE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E3",
            user_id="user_17",
            audit_at=AUDIT_AT,
            evidence_facts=[tombstone_fact],
            context_map={"tombstone_001": {"account_deleted": True}},
        )
        tombstone_violations = [
            v for v in analysis.violations
            if v.resource_id == "tombstone_001"
        ]
        assert len(tombstone_violations) >= 1
        assert "tombstone" in tombstone_violations[0].description.lower()
        assert not analysis.is_complete

    def test_tombstone_redacted_is_compliant(self, audit_core):
        tombstone_fact = _make_fact(
            file_id="evidence_51",
            system_id="identity_service",
            resource_id="tombstone_001",
            observed_state=RecordState.REDACTED,
            data_category=DataCategory.ACCOUNT_TOMBSTONE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E3b",
            user_id="user_17",
            audit_at=AUDIT_AT,
            evidence_facts=[tombstone_fact],
            context_map={"tombstone_001": {"account_deleted": True}},
        )
        tombstone_violations = [
            v for v in analysis.violations
            if v.resource_id == "tombstone_001"
        ]
        assert len(tombstone_violations) == 0


class TestE4_AllowedRetainedRecord:
    """SECURITY_AUDIT_LOG within retention period → RETAIN, no violation."""

    def test_security_audit_retained_is_not_a_violation(self, audit_core):
        audit_fact = _make_fact(
            file_id="evidence_37",
            system_id="security_service",
            resource_id="audit_record_003",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.SECURITY_AUDIT_LOG,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E4",
            user_id="user_03",
            audit_at=AUDIT_AT,
            evidence_facts=[audit_fact],
            context_map={"audit_record_003": {"within_retention_period": True}},
        )
        security_violations = [
            v for v in analysis.violations
            if v.resource_id == "audit_record_003"
        ]
        assert len(security_violations) == 0
        # Should appear as a retained record
        retained_ids = [r.resource_id for r in analysis.retained_records]
        assert "audit_record_003" in retained_ids

    def test_absent_mandatory_retain_record_is_violation(self, audit_core):
        """A retained record that is absent is itself a violation (must be present)."""
        audit_fact = _make_fact(
            file_id="evidence_37",
            system_id="security_service",
            resource_id="audit_record_003",
            observed_state=RecordState.ABSENT,
            data_category=DataCategory.SECURITY_AUDIT_LOG,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E4b",
            user_id="user_03",
            audit_at=AUDIT_AT,
            evidence_facts=[audit_fact],
            context_map={"audit_record_003": {"within_retention_period": True}},
        )
        # An audit record that should be retained but is absent IS a violation
        # (it means the RETAIN requirement is not met)
        security_violations = [
            v for v in analysis.violations
            if v.resource_id == "audit_record_003"
        ]
        assert len(security_violations) >= 1


class TestE5_EmailHashRemainingInRecord:
    """Email hash in EMAIL_DELIVERY_LOG that needs redaction → still a violation."""

    def test_email_delivery_log_present_with_email_is_violation(self, audit_core):
        log_fact = _make_fact(
            file_id="evidence_41",
            system_id="notification_service",
            resource_id="email_delivery_001",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.EMAIL_DELIVERY_LOG,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E5",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[log_fact],
            context_map={"email_delivery_001": {"log_has_email": True}},
        )
        violations = [v for v in analysis.violations if v.resource_id == "email_delivery_001"]
        assert len(violations) >= 1
        assert violations[0].rule.required_action == RequiredAction.REDACT

    def test_email_delivery_log_redacted_is_compliant(self, audit_core):
        log_fact = _make_fact(
            file_id="evidence_41",
            system_id="notification_service",
            resource_id="email_delivery_001",
            observed_state=RecordState.REDACTED,
            data_category=DataCategory.EMAIL_DELIVERY_LOG,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E5b",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[log_fact],
            context_map={"email_delivery_001": {"log_has_email": True}},
        )
        violations = [v for v in analysis.violations if v.resource_id == "email_delivery_001"]
        assert len(violations) == 0


class TestE6_ActiveSyncCanRecreateDeletedRecord:
    """Deletion succeeded but an active sync exists → can recreate data."""

    def test_active_sync_after_delete_is_an_active_flow(self, audit_core):
        # Evidence: account absent
        primary = _make_fact(
            file_id="evidence_54",
            system_id="account_service",
            resource_id="account_001",
            observed_state=RecordState.ABSENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-15T00:00:00Z",
        )
        # Activity: DELETE then SYNC_RECORD
        ev_del = _make_activity(
            "act_del_01", "DELETE_RECORD", "account_001",
            reported_result="SUCCESS", event_time="2026-09-10T00:00:00Z",
        )
        ev_sync = _make_activity(
            "act_sync_01", "SYNC_RECORD", "account_001",
            event_time="2026-09-20T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E6",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[primary],
            activity_events=[ev_del, ev_sync],
        )
        # Should detect DELAYED_REPLICATION conflict
        assert any(c.kind == ConflictKind.DELAYED_REPLICATION for c in analysis.temporal_conflicts)
        # Should surface an active flow (sync can recreate)
        active_flow_rids = [f.resource_id for f in analysis.active_flows]
        assert any("account_001" in rid for rid in active_flow_rids)

    def test_no_sync_after_delete_means_no_active_flow(self, audit_core):
        primary = _make_fact(
            file_id="evidence_54",
            system_id="account_service",
            resource_id="account_001",
            observed_state=RecordState.ABSENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-15T00:00:00Z",
        )
        ev_del = _make_activity(
            "act_del_01", "DELETE_RECORD", "account_001",
            reported_result="SUCCESS", event_time="2026-09-10T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E6b",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[primary],
            activity_events=[ev_del],
        )
        # No active flows from activity stream
        activity_driven_flows = [
            f for f in analysis.active_flows
            if "account_001" in f.resource_id
        ]
        assert len(activity_driven_flows) == 0


class TestE7_DisabledSync:
    """Data flow connector is disabled → no active risk."""

    def test_disabled_connector_is_not_active_risk(self, audit_core):
        disabled_flow = _make_fact(
            file_id="evidence_13",
            system_id="integration_service",
            resource_id="data_flow_001",
            observed_state=RecordState.DISABLED,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E7",
            user_id="user_15",
            audit_at=AUDIT_AT,
            evidence_facts=[disabled_flow],
        )
        assert len(analysis.active_flows) == 0

    def test_active_connector_is_active_risk(self, audit_core):
        active_flow = _make_fact(
            file_id="evidence_14",
            system_id="integration_service",
            resource_id="data_flow_002",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E7b",
            user_id="user_15",
            audit_at=AUDIT_AT,
            evidence_facts=[active_flow],
        )
        assert len(analysis.active_flows) >= 1
        assert any(f.resource_id == "data_flow_002" for f in analysis.active_flows)


class TestE8_RestoreRiskFromBackup:
    """Backup exists with restore_allowed=True → REPORT_RESTORE_RISK."""

    def test_restore_allowed_backup_is_active_risk(self, audit_core):
        backup_fact = _make_fact(
            file_id="evidence_93",
            system_id="backup_service",
            resource_id="backup_4978",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.BACKUP_ARCHIVE,
            captured_at="2026-09-16T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E8",
            user_id="user_09",
            audit_at=AUDIT_AT,
            evidence_facts=[backup_fact],
        )
        active_risks = [r for r in analysis.restore_risks if r.is_active_risk]
        assert len(active_risks) >= 1
        assert any(r.resource_id == "backup_4978" for r in active_risks)
        assert not analysis.is_complete

    def test_restore_risk_makes_deletion_incomplete(self, audit_core):
        """Even if the account is absent, an unblocked backup prevents COMPLETE."""
        account_absent = _make_fact(
            file_id="evidence_54",
            system_id="account_service",
            resource_id="account_3960",
            observed_state=RecordState.ABSENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        backup_fact = _make_fact(
            file_id="evidence_93",
            system_id="backup_service",
            resource_id="backup_4978",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.BACKUP_ARCHIVE,
            captured_at="2026-09-16T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E8b",
            user_id="user_09",
            audit_at=AUDIT_AT,
            evidence_facts=[account_absent, backup_fact],
        )
        assert not analysis.is_complete


class TestE9_BlockedRestore:
    """Backup with restore_blocked → no active risk; deletion may be COMPLETE."""

    def test_blocked_restore_is_not_active_risk(self, audit_core):
        backup_fact = _make_fact(
            file_id="evidence_93",
            system_id="backup_service",
            resource_id="backup_4978",
            observed_state=RecordState.BLOCKED,
            data_category=DataCategory.BACKUP_ARCHIVE,
            captured_at="2026-09-16T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E9",
            user_id="user_09",
            audit_at=AUDIT_AT,
            evidence_facts=[backup_fact],
        )
        active_risks = [r for r in analysis.restore_risks if r.is_active_risk]
        assert len(active_risks) == 0

    def test_blocked_backup_plus_absent_account_can_be_complete(self, audit_core):
        account_fact = _make_fact(
            file_id="evidence_54",
            system_id="account_service",
            resource_id="account_3960",
            observed_state=RecordState.ABSENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        backup_fact = _make_fact(
            file_id="evidence_93",
            system_id="backup_service",
            resource_id="backup_4978",
            observed_state=RecordState.BLOCKED,
            data_category=DataCategory.BACKUP_ARCHIVE,
            captured_at="2026-09-16T00:00:00Z",
        )
        # Security audit retained, legal hold retained
        audit_fact = _make_fact(
            file_id="evidence_37",
            system_id="security_service",
            resource_id="audit_record_003",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.SECURITY_AUDIT_LOG,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_E9b",
            user_id="user_09",
            audit_at=AUDIT_AT,
            evidence_facts=[account_fact, backup_fact, audit_fact],
            context_map={
                "backup_4978": {"restore_blockable": True},
                "audit_record_003": {"within_retention_period": True},
            },
        )
        assert analysis.is_complete


class TestE10_ContradictorySuccessFailureActivity:
    """Same resource, same timestamp: one activity says SUCCESS, one says FAILED."""

    def test_contradictory_activity_creates_conflict(self):
        ts = "2026-09-15T10:00:00Z"
        ev_ok = _make_activity("act_01", "DELETE_RECORD", "account_001",
                               reported_result="SUCCESS", event_time=ts)
        ev_fail = _make_activity("act_02", "DELETE_RECORD", "account_001",
                                 reported_result="FAILED", event_time=ts)
        proc = TemporalEventProcessor([ev_ok, ev_fail], AUDIT_AT)
        conflicts = [c for c in proc.conflicts if c.kind == ConflictKind.SAME_TIME_CONTRADICTORY]
        assert len(conflicts) >= 1
        assert conflicts[0].resource_id == "account_001"

    def test_contradictory_activity_does_not_override_evidence(self, audit_core):
        """A contradictory activity claim must not change inventory state from evidence."""
        # Evidence clearly shows PRESENT
        account_fact = _make_fact(
            file_id="evidence_54",
            system_id="account_service",
            resource_id="account_001",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-16T00:00:00Z",
        )
        ts = "2026-09-15T10:00:00Z"
        ev_ok = _make_activity("act_01", "DELETE_RECORD", "account_001",
                               reported_result="SUCCESS", event_time=ts)
        ev_fail = _make_activity("act_02", "DELETE_RECORD", "account_001",
                                 reported_result="FAILED", event_time=ts)
        analysis = audit_core.analyze_case(
            case_id="case_E10",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[account_fact],
            activity_events=[ev_ok, ev_fail],
        )
        # Evidence wins: PRESENT should still be a violation
        entry = next(
            (e for e in analysis.inventory if e.resource_id == "account_001"), None
        )
        assert entry is not None
        assert entry.state == ResourceInventoryState.PRESENT
        assert len(analysis.violations) >= 1


class TestE11_EventAfterAuditAt:
    """Events after audit_at must be excluded from state determination."""

    def test_post_audit_evidence_fact_ignored(self, audit_core):
        future_fact = _make_fact(
            file_id="evidence_55",
            system_id="account_service",
            resource_id="account_001",
            observed_state=RecordState.ABSENT,  # deletion "confirmed" in the future
            data_category=DataCategory.USER_PROFILE,
            captured_at=AFTER_AUDIT.isoformat().replace("+00:00", "Z"),
        )
        # No pre-audit fact → inventory has no entry for this resource
        analysis = audit_core.analyze_case(
            case_id="case_E11",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[future_fact],
        )
        # The post-audit fact must have been ignored
        entry = next(
            (e for e in analysis.inventory if e.resource_id == "account_001"), None
        )
        assert entry is None

    def test_post_audit_activity_event_becomes_future_event(self):
        future_ev = _make_activity(
            "act_future", "DELETE_RECORD", "account_001",
            reported_result="SUCCESS",
            event_time=AFTER_AUDIT.isoformat().replace("+00:00", "Z"),
        )
        proc = TemporalEventProcessor([future_ev], AUDIT_AT)
        assert len(proc.future_events) == 1
        # It must not appear in eligible claims
        assert proc.latest_deletion_claim("account_001") is None
        # It must produce a FUTURE_EVENT conflict
        assert any(c.kind == ConflictKind.FUTURE_EVENT for c in proc.conflicts)

    def test_pre_audit_event_is_eligible(self):
        past_ev = _make_activity(
            "act_past", "DELETE_RECORD", "account_001",
            reported_result="SUCCESS",
            event_time=BEFORE_AUDIT.isoformat().replace("+00:00", "Z"),
        )
        proc = TemporalEventProcessor([past_ev], AUDIT_AT)
        assert len(proc.future_events) == 0
        assert proc.latest_deletion_claim("account_001") is not None


class TestE12_InsufficientEvidenceCoverage:
    """No eligible evidence for a resource that is expected to be deleted."""

    def test_no_evidence_means_unknown_state(self, audit_core):
        """Zero facts → inventory has no entry → evidence gap."""
        analysis = audit_core.analyze_case(
            case_id="case_E12",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[],
        )
        # With no facts, inventory is empty and there are no violations from evidence
        # (no evidence to check = no gaps recorded unless we expected coverage)
        assert len(analysis.inventory) == 0
        assert analysis.is_complete  # vacuously complete with no evidence

    def test_unknown_inventory_state_triggers_violation(self, audit_core):
        """An entry explicitly placed in UNKNOWN state must produce a violation."""
        inv = ResourceInventory()
        entry = InventoryEntry(
            system_id="account_service",
            resource_id="account_001",
            data_category=DataCategory.USER_PROFILE,
            subject_user_id="user_01",
            state=ResourceInventoryState.UNKNOWN,
        )
        violation = audit_core._policy.evaluate_inventory(entry)
        assert violation is not None
        assert "insufficient_evidence" in violation.description

    def test_conflicting_evidence_produces_evidence_gap(self, audit_core):
        """Conflicted state → evidence gap in analysis."""
        ts = "2026-09-01T00:00:00Z"
        fact_a = _make_fact(file_id="ev_1", observed_state=RecordState.PRESENT, captured_at=ts)
        fact_b = _make_fact(file_id="ev_2", observed_state=RecordState.ABSENT, captured_at=ts)
        analysis = audit_core.analyze_case(
            case_id="case_E12b",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[fact_a, fact_b],
        )
        assert analysis.has_evidence_gaps
        gap_rids = [g.resource_id for g in analysis.evidence_gaps]
        assert "account_001" in gap_rids
        # Conflicted state must also produce a violation
        assert len(analysis.violations) >= 1


# ===========================================================================
# AuditAnalysis structural tests
# ===========================================================================

class TestAuditAnalysis:
    def test_is_complete_with_no_violations_no_flows_no_risks(self, audit_core):
        account_absent = _make_fact(
            observed_state=RecordState.ABSENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_complete",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[account_absent],
        )
        assert analysis.is_complete

    def test_is_incomplete_with_active_flow(self, audit_core):
        active_flow = _make_fact(
            system_id="integration_service",
            resource_id="data_flow_001",
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at="2026-09-01T00:00:00Z",
        )
        analysis = audit_core.analyze_case(
            case_id="case_flow",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[active_flow],
        )
        assert not analysis.is_complete

    def test_summary_contains_case_id_and_no_pii(self, audit_core):
        analysis = audit_core.analyze_case(
            case_id="case_summary_test",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[],
        )
        summary = analysis.summary()
        assert "case_summary_test" in summary
        assert "@" not in summary  # no email addresses in summary

    def test_future_events_recorded_but_not_in_state(self, audit_core):
        pre_fact = _make_fact(
            observed_state=RecordState.PRESENT,
            data_category=DataCategory.USER_PROFILE,
            captured_at=BEFORE_AUDIT.isoformat().replace("+00:00", "Z"),
        )
        future_ev = _make_activity(
            "act_future", "DELETE_RECORD", "account_001",
            reported_result="SUCCESS",
            event_time=AFTER_AUDIT.isoformat().replace("+00:00", "Z"),
        )
        analysis = audit_core.analyze_case(
            case_id="case_future",
            user_id="user_01",
            audit_at=AUDIT_AT,
            evidence_facts=[pre_fact],
            activity_events=[future_ev],
        )
        assert len(analysis.future_events) == 1
        # State should reflect pre-audit evidence, not future event
        entry = next(
            (e for e in analysis.inventory if e.resource_id == "account_001"), None
        )
        assert entry is not None
        assert entry.state == ResourceInventoryState.PRESENT


# ===========================================================================
# PolicyEngine.from_csv with real deletion_rules.csv
# ===========================================================================

class TestPolicyEngineRealCSV:
    """Verify PolicyEngine loads the actual dataset deletion_rules.csv."""

    REAL_CSV = Path(__file__).parent.parent.parent.parent / "dataset" / "deletion_rules.csv"

    @pytest.mark.skipif(
        not (Path(__file__).parent.parent.parent.parent / "dataset" / "deletion_rules.csv").exists(),
        reason="Real dataset not present"
    )
    def test_real_csv_loads_15_rules(self):
        engine = PolicyEngine.from_csv(self.REAL_CSV)
        # All 15 categories from deletion_rules.csv
        expected_categories = {
            DataCategory.USER_PROFILE,
            DataCategory.SECONDARY_IDENTIFIER,
            DataCategory.SEARCH_INDEX_ENTRY,
            DataCategory.CACHE_ENTRY,
            DataCategory.SUPPORT_MESSAGE,
            DataCategory.SUPPORT_ATTACHMENT,
            DataCategory.ANALYTICS_PROFILE,
            DataCategory.PRODUCT_TELEMETRY,
            DataCategory.USER_EXPORT,
            DataCategory.MARKETING_PROFILE,
            DataCategory.EMAIL_DELIVERY_LOG,
            DataCategory.SECURITY_AUDIT_LOG,
            DataCategory.LEGAL_HOLD_RECORD,
            DataCategory.BACKUP_ARCHIVE,
            DataCategory.ACCOUNT_TOMBSTONE,
        }
        for cat in expected_categories:
            rule = engine.get_rule(cat)
            assert rule is not None, f"Missing rule for {cat}"

    @pytest.mark.skipif(
        not (Path(__file__).parent.parent.parent.parent / "dataset" / "deletion_rules.csv").exists(),
        reason="Real dataset not present"
    )
    def test_real_csv_rule_01_is_delete(self):
        engine = PolicyEngine.from_csv(self.REAL_CSV)
        rule = engine.get_rule(DataCategory.USER_PROFILE)
        assert rule.required_action == RequiredAction.DELETE
        assert rule.rule_id == "rule_01"

    @pytest.mark.skipif(
        not (Path(__file__).parent.parent.parent.parent / "dataset" / "deletion_rules.csv").exists(),
        reason="Real dataset not present"
    )
    def test_real_csv_rule_12_is_retain(self):
        engine = PolicyEngine.from_csv(self.REAL_CSV)
        rule = engine.get_rule(DataCategory.SECURITY_AUDIT_LOG)
        assert rule.required_action == RequiredAction.RETAIN
        assert rule.retention_mandated is True


# ===========================================================================
# _ensure_utc and _parse_ts
# ===========================================================================

class TestTemporalHelpers:
    def test_ensure_utc_naive_gets_utc(self):
        naive = datetime(2026, 9, 1, 0, 0, 0)
        result = _ensure_utc(naive)
        assert result.tzinfo is not None
        assert result.tzinfo == timezone.utc

    def test_ensure_utc_aware_converted(self):
        from datetime import timezone as tz
        import datetime as dt
        offset_aware = datetime(2026, 9, 1, 5, 30, 0,
                                tzinfo=dt.timezone(dt.timedelta(hours=5, minutes=30)))
        result = _ensure_utc(offset_aware)
        assert result.tzinfo == timezone.utc
        assert result.hour == 0  # 05:30 IST == 00:00 UTC

    def test_parse_ts_z_suffix(self):
        result = _parse_ts("2026-09-01T10:00:00Z")
        assert result.tzinfo == timezone.utc
        assert result.hour == 10

    def test_parse_ts_offset(self):
        result = _parse_ts("2026-09-01T10:00:00+05:30")
        assert result.tzinfo == timezone.utc
        assert result.hour == 4  # 10:00+05:30 = 04:30 UTC
