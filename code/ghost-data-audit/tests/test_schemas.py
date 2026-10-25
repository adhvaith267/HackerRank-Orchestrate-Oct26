"""
test_schemas.py — Unit tests for schemas.py.

Tests:
  - All enum values are present and correct
  - OPERATION_STATE_MAP is complete (covers all operations)
  - validate_operation_state accepts valid pairs
  - validate_operation_state rejects invalid pairs
  - validate_operation_phase accepts valid assignments
  - validate_operation_phase rejects invalid assignments
  - AuditStep rejects mismatched operation/state
  - AuditStep rejects mismatched operation/phase
  - CaseResult validates step_no sequencing
  - CaseResult validates phase ordering
  - RequestCase parses timestamps to UTC-aware datetimes
  - RequestCase rejects malformed case_id
  - EvidenceRef infers format from file extension
  - EvidenceFact normalises email to lowercase
"""

import pytest
from datetime import datetime, timezone

from ghost_audit.schemas import (
    OPERATION_STATE_MAP,
    PHASE_OPERATIONS,
    AuditFinding,
    AuditStep,
    CaseResult,
    DataCategory,
    DeletionStatus,
    EvidenceFact,
    EvidenceFormat,
    EvidenceRef,
    Operation,
    Phase,
    RecordState,
    RequestCase,
    RequiredAction,
    ReportedStatus,
    validate_operation_phase,
    validate_operation_state,
)


# ---------------------------------------------------------------------------
# Enum completeness
# ---------------------------------------------------------------------------

class TestEnumCompleteness:
    def test_operation_state_map_covers_all_operations(self):
        for op in Operation:
            assert op in OPERATION_STATE_MAP, f"Operation {op} missing from OPERATION_STATE_MAP"

    def test_phase_operations_covers_all_operations(self):
        all_ops = set()
        for ops in PHASE_OPERATIONS.values():
            all_ops |= ops
        for op in Operation:
            assert op in all_ops, f"Operation {op} not in any phase"

    def test_phase_operations_no_overlap(self):
        seen = set()
        for phase, ops in PHASE_OPERATIONS.items():
            for op in ops:
                assert op not in seen, f"Operation {op} appears in multiple phases"
                seen.add(op)

    def test_required_action_values(self):
        values = {a.value for a in RequiredAction}
        assert values == {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}

    def test_record_state_values(self):
        expected = {"PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"}
        assert {s.value for s in RecordState} == expected

    def test_data_category_count(self):
        # 15 rules in deletion_rules.csv → 15 data categories
        assert len(DataCategory) == 15

    def test_phase_order(self):
        order = Phase.order()
        assert order == [Phase.FINDING, Phase.REMEDIATION, Phase.VERIFICATION]


# ---------------------------------------------------------------------------
# validate_operation_state
# ---------------------------------------------------------------------------

class TestValidateOperationState:
    @pytest.mark.parametrize("op,state", [
        (Operation.REPORT_REMAINING_RECORD, RecordState.PRESENT),
        (Operation.REPORT_EXPOSED_PII, RecordState.PRESENT),
        (Operation.REPORT_ACTIVE_DATA_FLOW, RecordState.ACTIVE),
        (Operation.REPORT_RESTORE_RISK, RecordState.ACTIVE),
        (Operation.DISABLE_DATA_FLOW, RecordState.DISABLED),
        (Operation.BLOCK_RESTORE, RecordState.BLOCKED),
        (Operation.DELETE_RECORD, RecordState.ABSENT),
        (Operation.REDACT_RECORD, RecordState.REDACTED),
        (Operation.ANONYMIZE_RECORD, RecordState.ANONYMIZED),
        (Operation.VERIFY_RECORD_ABSENT, RecordState.ABSENT),
        (Operation.VERIFY_RECORD_PRESENT, RecordState.PRESENT),
        (Operation.VERIFY_RECORD_REDACTED, RecordState.REDACTED),
        (Operation.VERIFY_RECORD_ANONYMIZED, RecordState.ANONYMIZED),
        (Operation.VERIFY_DATA_FLOW_DISABLED, RecordState.DISABLED),
        (Operation.VERIFY_RESTORE_BLOCKED, RecordState.BLOCKED),
    ])
    def test_valid_pairs_pass(self, op, state):
        validate_operation_state(op, state)  # Should not raise

    @pytest.mark.parametrize("op,bad_state", [
        (Operation.REPORT_REMAINING_RECORD, RecordState.ABSENT),
        (Operation.DELETE_RECORD, RecordState.PRESENT),
        (Operation.REDACT_RECORD, RecordState.ABSENT),
        (Operation.VERIFY_RECORD_ABSENT, RecordState.PRESENT),
        (Operation.VERIFY_RECORD_PRESENT, RecordState.ABSENT),
        (Operation.DISABLE_DATA_FLOW, RecordState.PRESENT),
        (Operation.BLOCK_RESTORE, RecordState.PRESENT),
    ])
    def test_invalid_pairs_raise(self, op, bad_state):
        with pytest.raises(ValueError, match="requires state"):
            validate_operation_state(op, bad_state)


# ---------------------------------------------------------------------------
# validate_operation_phase
# ---------------------------------------------------------------------------

class TestValidateOperationPhase:
    @pytest.mark.parametrize("op,phase", [
        (Operation.REPORT_REMAINING_RECORD, Phase.FINDING),
        (Operation.REPORT_ACTIVE_DATA_FLOW, Phase.FINDING),
        (Operation.DELETE_RECORD, Phase.REMEDIATION),
        (Operation.DISABLE_DATA_FLOW, Phase.REMEDIATION),
        (Operation.VERIFY_RECORD_ABSENT, Phase.VERIFICATION),
        (Operation.VERIFY_RESTORE_BLOCKED, Phase.VERIFICATION),
    ])
    def test_valid_phase_ops_pass(self, op, phase):
        validate_operation_phase(op, phase)  # Should not raise

    @pytest.mark.parametrize("op,wrong_phase", [
        (Operation.REPORT_REMAINING_RECORD, Phase.REMEDIATION),
        (Operation.REPORT_REMAINING_RECORD, Phase.VERIFICATION),
        (Operation.DELETE_RECORD, Phase.FINDING),
        (Operation.DELETE_RECORD, Phase.VERIFICATION),
        (Operation.VERIFY_RECORD_ABSENT, Phase.FINDING),
        (Operation.VERIFY_RECORD_ABSENT, Phase.REMEDIATION),
    ])
    def test_wrong_phase_raises(self, op, wrong_phase):
        with pytest.raises(ValueError, match="does not belong to phase"):
            validate_operation_phase(op, wrong_phase)


# ---------------------------------------------------------------------------
# AuditStep construction and validation
# ---------------------------------------------------------------------------

class TestAuditStep:
    def test_valid_finding_step(self):
        step = AuditStep(
            step_no=1,
            phase=Phase.FINDING,
            system_id="account_service",
            resource_id="account_001",
            operation=Operation.REPORT_REMAINING_RECORD,
            state=RecordState.PRESENT,
            evidence_id="evidence_01",
        )
        assert step.step_no == 1

    def test_valid_remediation_step(self):
        step = AuditStep(
            step_no=2,
            phase=Phase.REMEDIATION,
            system_id="account_service",
            resource_id="account_001",
            operation=Operation.DELETE_RECORD,
            state=RecordState.ABSENT,
            evidence_id="",
        )
        assert step.evidence_id == ""

    def test_valid_verification_step(self):
        step = AuditStep(
            step_no=3,
            phase=Phase.VERIFICATION,
            system_id="account_service",
            resource_id="account_001",
            operation=Operation.VERIFY_RECORD_ABSENT,
            state=RecordState.ABSENT,
            evidence_id="evidence_54",
        )
        assert step.operation == Operation.VERIFY_RECORD_ABSENT

    def test_mismatched_state_raises(self):
        with pytest.raises(Exception):
            AuditStep(
                step_no=1,
                phase=Phase.FINDING,
                system_id="account_service",
                resource_id="account_001",
                operation=Operation.REPORT_REMAINING_RECORD,
                state=RecordState.ABSENT,  # Wrong: should be PRESENT
                evidence_id="evidence_01",
            )

    def test_mismatched_phase_raises(self):
        with pytest.raises(Exception):
            AuditStep(
                step_no=1,
                phase=Phase.VERIFICATION,  # Wrong phase for REPORT_REMAINING_RECORD
                system_id="account_service",
                resource_id="account_001",
                operation=Operation.REPORT_REMAINING_RECORD,
                state=RecordState.PRESENT,
                evidence_id="evidence_01",
            )

    def test_to_output_dict_has_required_fields(self):
        step = AuditStep(
            step_no=1,
            phase=Phase.FINDING,
            system_id="account_service",
            resource_id="account_001",
            operation=Operation.REPORT_REMAINING_RECORD,
            state=RecordState.PRESENT,
            evidence_id="evidence_01",
        )
        d = step.to_output_dict()
        assert set(d.keys()) == {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
        assert d["phase"] == "FINDING"
        assert d["operation"] == "REPORT_REMAINING_RECORD"
        assert d["state"] == "PRESENT"


# ---------------------------------------------------------------------------
# CaseResult validation
# ---------------------------------------------------------------------------

def _make_step(step_no, phase, op, state, ev=""):
    return AuditStep(
        step_no=step_no, phase=phase,
        system_id="account_service", resource_id="account_001",
        operation=op, state=state, evidence_id=ev,
    )


class TestCaseResult:
    def test_not_applicable_empty_steps(self):
        result = CaseResult(
            case_id="case_01",
            deletion_status=DeletionStatus.NOT_APPLICABLE,
            steps=[],
        )
        assert result.not_applicable

    def test_valid_complete_result(self):
        steps = [
            _make_step(1, Phase.VERIFICATION, Operation.VERIFY_RECORD_ABSENT, RecordState.ABSENT, "evidence_54"),
        ]
        result = CaseResult(
            case_id="case_01",
            deletion_status=DeletionStatus.COMPLETE,
            steps=steps,
        )
        assert result.deletion_status == DeletionStatus.COMPLETE

    def test_step_no_sequencing_error(self):
        steps = [
            _make_step(1, Phase.FINDING, Operation.REPORT_REMAINING_RECORD, RecordState.PRESENT, "ev_01"),
            _make_step(3, Phase.REMEDIATION, Operation.DELETE_RECORD, RecordState.ABSENT),  # step_no=3 not 2
        ]
        with pytest.raises(ValueError, match="Step numbering broken"):
            CaseResult(
                case_id="case_99",
                deletion_status=DeletionStatus.INCOMPLETE,
                steps=steps,
            )

    def test_phase_order_violation(self):
        steps = [
            _make_step(1, Phase.VERIFICATION, Operation.VERIFY_RECORD_ABSENT, RecordState.ABSENT),
            _make_step(2, Phase.FINDING, Operation.REPORT_REMAINING_RECORD, RecordState.PRESENT, "ev_01"),
        ]
        with pytest.raises(ValueError, match="Phase order violated"):
            CaseResult(
                case_id="case_99",
                deletion_status=DeletionStatus.INCOMPLETE,
                steps=steps,
            )

    def test_to_output_row_format(self):
        import json
        steps = [
            _make_step(1, Phase.VERIFICATION, Operation.VERIFY_RECORD_ABSENT, RecordState.ABSENT, "evidence_54"),
        ]
        result = CaseResult(
            case_id="case_01",
            deletion_status=DeletionStatus.COMPLETE,
            steps=steps,
        )
        row = result.to_output_row()
        assert row["case_id"] == "case_01"
        assert row["deletion_status"] == "COMPLETE"
        parsed = json.loads(row["steps_json"])
        assert isinstance(parsed, list)
        assert parsed[0]["step_no"] == 1


# ---------------------------------------------------------------------------
# RequestCase
# ---------------------------------------------------------------------------

class TestRequestCase:
    def test_valid_request_case(self):
        case = RequestCase(
            case_id="case_01",
            email="test@example.com",
            requested_at_raw="2026-08-18T09:14:00Z",
            requested_at=datetime(2026, 8, 18, 9, 14, tzinfo=timezone.utc),
            reported_status=ReportedStatus.COMPLETE,
            reported_at_raw="2026-08-20T16:42:00Z",
            reported_at=datetime(2026, 8, 20, 16, 42, tzinfo=timezone.utc),
            audit_at_raw="2026-09-03T11:30:00Z",
            audit_at=datetime(2026, 9, 3, 11, 30, tzinfo=timezone.utc),
            request_text="Please delete my account.",
        )
        assert case.email == "test@example.com"
        assert case.audit_at.tzinfo is not None

    def test_email_lowercased(self):
        case = RequestCase(
            case_id="case_01",
            email="TEST@EXAMPLE.COM",
            requested_at_raw="2026-01-01T00:00:00Z",
            requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            reported_status=ReportedStatus.COMPLETE,
            reported_at_raw="2026-01-01T00:00:00Z",
            reported_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            audit_at_raw="2026-01-02T00:00:00Z",
            audit_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            request_text="Delete me.",
        )
        assert case.email == "test@example.com"

    def test_invalid_case_id_raises(self):
        with pytest.raises(Exception):
            RequestCase(
                case_id="invalid_id",  # must match case_<N>
                email="a@b.com",
                requested_at_raw="2026-01-01T00:00:00Z",
                requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                reported_status=ReportedStatus.COMPLETE,
                reported_at_raw="2026-01-01T00:00:00Z",
                reported_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                audit_at_raw="2026-01-02T00:00:00Z",
                audit_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                request_text="Delete me.",
            )


# ---------------------------------------------------------------------------
# EvidenceRef
# ---------------------------------------------------------------------------

class TestEvidenceRef:
    def test_sql_format_inferred(self):
        ref = EvidenceRef(
            file_id="evidence_01",
            file_path="evidence/databases/customer_data_inventory_20260213.sql",
            origin="customer_data_inventory_capture",
            captured_at_raw="2026-02-13T07:43:27Z",
            captured_at=datetime(2026, 2, 13, 7, 43, 27, tzinfo=timezone.utc),
            format="evidence/databases/customer_data_inventory_20260213.sql",
        )
        assert ref.format == EvidenceFormat.SQL

    def test_json_format_inferred(self):
        ref = EvidenceRef(
            file_id="evidence_02",
            file_path="evidence/records/customer_data_snapshot_bundle_20260917.json",
            origin="records_assurance_snapshot_bundle",
            captured_at_raw="2026-09-17T12:00:00Z",
            captured_at=datetime(2026, 9, 17, 12, tzinfo=timezone.utc),
            format="evidence/records/customer_data_snapshot_bundle_20260917.json",
        )
        assert ref.format == EvidenceFormat.JSON

    def test_image_format_inferred(self):
        ref = EvidenceRef(
            file_id="evidence_04",
            file_path="evidence/images/account_admin_console_20260926.png",
            origin="account_admin_portal",
            captured_at_raw="2026-09-26T11:00:00Z",
            captured_at=datetime(2026, 9, 26, 11, tzinfo=timezone.utc),
            format="evidence/images/account_admin_console_20260926.png",
        )
        assert ref.format == EvidenceFormat.IMAGE

    def test_invalid_file_id_raises(self):
        with pytest.raises(Exception):
            EvidenceRef(
                file_id="ev_01",  # must match evidence_<N>
                file_path="evidence/logs/something.log",
                origin="test",
                captured_at_raw="2026-01-01T00:00:00Z",
                captured_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                format="evidence/logs/something.log",
            )
