from datetime import datetime, timezone
from pathlib import Path

from ghost_audit.audit_engine import AuditEngine
from ghost_audit.config import RunConfig, load_config
from ghost_audit.evidence import EvidenceLoader
from ghost_audit.identity import IdentityResolver
from ghost_audit.llm import LLMClient
from ghost_audit.output_writer import validate_output
from ghost_audit.schemas import (
    DataCategory,
    DeletionStatus,
    EvidenceFact,
    LLMConfidence,
    RecordState,
    ReportedStatus,
    RequestCase,
    EvidenceRef,
    EvidenceFormat,
)


def _case(email: str) -> RequestCase:
    return RequestCase(
        case_id="case_999",
        email=email,
        requested_at="2026-01-01T00:00:00Z",
        requested_at_raw="2026-01-01T00:00:00Z",
        reported_status=ReportedStatus.NOT_STARTED,
        reported_at="2026-01-01T00:00:00Z",
        reported_at_raw="2026-01-01T00:00:00Z",
        audit_at="2026-01-02T00:00:00Z",
        audit_at_raw="2026-01-02T00:00:00Z",
        request_text="Please delete my personal data.",
    )


def _identity(email: str = "user@example.invalid"):
    return {"user_1": {
        "user_id": "user_1", "email": email, "email_hash": "", "phone": "",
        "updated_at": "2025-01-01T00:00:00Z",
    }}


def test_authorized_unknown_identity_is_incomplete_not_not_applicable():
    engine = AuditEngine(RunConfig(), {}, [], [], [], Path("dataset"))
    result = engine.audit_case(_case("missing@example.invalid"))
    assert result.deletion_status == DeletionStatus.INCOMPLETE
    assert result.needs_review is True


def test_authorized_without_eligible_evidence_is_not_complete():
    engine = AuditEngine(RunConfig(), _identity(), [], [], [], Path("dataset"))
    result = engine.audit_case(_case("user@example.invalid"))
    assert result.deletion_status == DeletionStatus.INCOMPLETE
    assert result.steps == []


def test_activity_sync_after_delete_is_included_as_recreation_risk():
    activity = [
        {"activity_id": "activity_delete", "event_time": "2026-01-01T00:00:00Z",
         "event_type": "DELETE_RECORD", "source_system": "deletion_worker",
         "target_system": "account_service", "resource_id": "account_1",
         "reported_result": "SUCCESS", "details": "delete account_1"},
        {"activity_id": "activity_sync", "event_time": "2026-01-01T01:00:00Z",
         "event_type": "SYNC_RECORD", "source_system": "account_service",
         "target_system": "search_service", "resource_id": "account_1",
         "reported_result": "SUCCESS", "details": "sync account_1"},
    ]
    engine = AuditEngine(RunConfig(), _identity(), [], [], [], Path("dataset"), activity_rows=activity)
    fact = EvidenceFact(
        file_id="evidence_1", file_path="evidence/x.txt",
        captured_at="2026-01-01T00:30:00Z", system_id="account_service",
        resource_id="account_1", subject_user_id="user_1",
        subject_email="user@example.invalid", data_category=DataCategory.USER_PROFILE,
        observed_state=RecordState.ABSENT, raw_value="account_1 absent",
    )
    engine._evidence_loader.load_facts_for_user = lambda *_args: [fact]
    result = engine.audit_case(_case("user@example.invalid"))
    assert result.deletion_status == DeletionStatus.INCOMPLETE
    assert any(step.operation.value == "REPORT_ACTIVE_DATA_FLOW" for step in result.steps)
    assert any(step.evidence_id == "activity_sync" for step in result.steps)


def test_current_email_collision_is_ambiguous():
    identities = {
        "user_a": {"user_id": "user_a", "email": "shared@example.invalid", "email_hash": "", "phone": "", "updated_at": "2025-01-01T00:00:00Z"},
        "user_b": {"user_id": "user_b", "email": "shared@example.invalid", "email_hash": "", "phone": "", "updated_at": "2025-01-01T00:00:00Z"},
    }
    result = IdentityResolver(identities, []).resolve("shared@example.invalid")
    assert result.found is False
    assert result.is_ambiguous is True


def test_ambiguous_authorization_never_calls_or_accepts_model():
    client = LLMClient(RunConfig().llm)
    client._llm_classify = lambda *_args: (_ for _ in ()).throw(AssertionError("model called"))
    result = client.classify_request("I need help with my account.")
    assert result.authorized is False


def test_legacy_classification_parser_rejects_string_boolean_and_extra_fields():
    for response in (
        '{"authorized":"false","reason":"x","confidence":"high"}',
        '{"authorized":false,"reason":"x","confidence":"high","extra":1}',
    ):
        try:
            LLMClient._parse_classify_response(response)
        except ValueError:
            pass
        else:
            raise AssertionError("unvalidated classification response accepted")


def test_snapshot_embedded_capture_time_is_preserved_for_cutoff(tmp_path):
    import json
    from datetime import datetime, timezone

    root = tmp_path
    (root / "snapshot.json").write_text(json.dumps({
        "snapshots": [{
            "captured_at": "2026-01-03T00:00:00Z",
            "data_store": "account_service", "collection": "customer_profiles",
            "records": [{"resource_id": "account_1", "user_id": "user_1", "email": "user@example.invalid"}],
        }]
    }), encoding="utf-8")
    ref = EvidenceRef(
        file_id="evidence_999", file_path="snapshot.json", origin="test",
        captured_at_raw="2026-01-01T00:00:00Z", captured_at="2026-01-01T00:00:00Z",
        format=EvidenceFormat.JSON,
    )
    resolution = IdentityResolver(_identity(), []).resolve("user@example.invalid")
    facts = EvidenceLoader([ref], root, RunConfig()).load_facts_for_user(
        resolution, datetime(2026, 1, 4, tzinfo=timezone.utc)
    )
    assert facts and facts[0].captured_at.isoformat() == "2026-01-03T00:00:00+00:00"


def test_complete_without_verification_steps_is_rejected(tmp_path):
    path = tmp_path / "output.csv"
    path.write_text("case_id,deletion_status,steps_json\ncase_1,COMPLETE,[]\n", encoding="utf-8")
    assert any("must contain verification steps" in error for error in validate_output(path, ["case_1"]))


def test_example_config_is_loadable_with_yaml_string_mode():
    config = load_config(Path("config.example.yaml"))
    assert config.llm.mode == "off"
