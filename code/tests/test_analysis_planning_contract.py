"""Contract tests for the AuditAnalysis-only final-step planner."""

from datetime import datetime, timezone
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ghost-data-audit" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ghost_audit.audit_core import (  # noqa: E402
    AuditAnalysis,
    InventoryEntry,
    PolicyViolation,
    ResourceInventoryState,
    RetainedRecord,
    RestoreRiskRecord,
    TypedPolicyRule,
    DataFlowRecord,
    FlowStatus,
)
from ghost_audit.schemas import (  # noqa: E402
    DataCategory,
    DeletionStatus,
    RequiredAction,
)
from main import generate_steps_from_analysis, select_deletion_status, serialize_steps_json  # noqa: E402


def _ts() -> datetime:
    return datetime(2026, 10, 1, tzinfo=timezone.utc)


def _entry(system: str, resource: str, category: DataCategory, action: RequiredAction, state: ResourceInventoryState, evidence: str) -> InventoryEntry:
    return InventoryEntry(
        system_id=system,
        resource_id=resource,
        data_category=category,
        subject_user_id="user_1",
        required_action=action,
        state=state,
        best_source_id=evidence,
        best_captured_at=_ts(),
        all_source_ids=[evidence],
    )


def test_complete_is_verification_only_and_uses_analysis_provenance() -> None:
    analysis = AuditAnalysis(case_id="case_1", user_id="user_1", audit_at=_ts())
    analysis.compliant_resources = [
        _entry("search_service", "search_2", DataCategory.SEARCH_INDEX_ENTRY, RequiredAction.DELETE, ResourceInventoryState.ABSENT_CONFIRMED, "e_2"),
        _entry("account_service", "account_1", DataCategory.USER_PROFILE, RequiredAction.DELETE, ResourceInventoryState.ABSENT_CONFIRMED, "e_1"),
        _entry("security_service", "audit_1", DataCategory.SECURITY_AUDIT_LOG, RequiredAction.RETAIN, ResourceInventoryState.PRESENT, "e_3"),
    ]
    analysis.retained_records = [RetainedRecord("security_service", "audit_1", "r", DataCategory.SECURITY_AUDIT_LOG, "e_3")]
    analysis.inventory = analysis.compliant_resources

    assert select_deletion_status(analysis, True) == DeletionStatus.COMPLETE
    steps = generate_steps_from_analysis(analysis, DeletionStatus.COMPLETE)
    assert [s.operation.value for s in steps] == ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT"]
    assert all(s.phase.value == "VERIFICATION" and s.evidence_id in {"e_1", "e_2", "e_3"} for s in steps)
    assert [s.step_no for s in steps] == [1, 2, 3]


def test_incomplete_has_three_phases_and_does_not_collapse_distinct_resources() -> None:
    analysis = AuditAnalysis(case_id="case_2", user_id="user_1", audit_at=_ts())
    rule = TypedPolicyRule("r", DataCategory.SEARCH_INDEX_ENTRY, "always", RequiredAction.DELETE, False, False)
    analysis.violations = [
        PolicyViolation("r", rule, "search_service", "search_b", ResourceInventoryState.PRESENT, ResourceInventoryState.ABSENT_CONFIRMED, evidence_source_id="e_b"),
        PolicyViolation("r", rule, "search_service", "search_a", ResourceInventoryState.PRESENT, ResourceInventoryState.ABSENT_CONFIRMED, evidence_source_id="e_a"),
    ]
    analysis.inventory = [
        _entry("search_service", "search_b", DataCategory.SEARCH_INDEX_ENTRY, RequiredAction.DELETE, ResourceInventoryState.PRESENT, "e_b"),
        _entry("search_service", "search_a", DataCategory.SEARCH_INDEX_ENTRY, RequiredAction.DELETE, ResourceInventoryState.PRESENT, "e_a"),
    ]
    steps = generate_steps_from_analysis(analysis, DeletionStatus.INCOMPLETE)
    assert [s.phase.value for s in steps] == ["FINDING"] * 2 + ["REMEDIATION"] * 2 + ["VERIFICATION"] * 2
    assert [s.resource_id for s in steps[:2]] == ["search_a", "search_b"]
    assert all(s.evidence_id for s in steps[:2])
    assert all(not s.evidence_id for s in steps[2:])
    assert [s.step_no for s in steps] == list(range(1, 7))


def test_not_applicable_and_serialization_are_exact_and_deterministic() -> None:
    analysis = AuditAnalysis(case_id="case_3", user_id="user_1", audit_at=_ts())
    assert select_deletion_status(analysis, False) == DeletionStatus.NOT_APPLICABLE
    assert generate_steps_from_analysis(analysis, DeletionStatus.NOT_APPLICABLE) == []
    steps = generate_steps_from_analysis(analysis, DeletionStatus.NOT_APPLICABLE)
    assert serialize_steps_json(steps) == "[]"
    assert json.loads(serialize_steps_json(steps)) == []
