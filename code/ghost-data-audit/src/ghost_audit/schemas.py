"""
schemas.py — Canonical data contracts for ghost-data-audit.

All public types are defined here. Other modules import from this module only;
no cross-module circular imports are introduced.

Discovery source: docs/DATA_DISCOVERY.md
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _parse_utc(value: str | datetime) -> datetime:
    """Parse an ISO-8601 UTC string to a timezone-aware datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    value = value.strip()
    # Accept trailing Z or +00:00
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Enumerations — sourced from AGENTS.md §6.3/§6.4 and deletion_rules.csv
# ---------------------------------------------------------------------------


class ReportedStatus(str, Enum):
    """Workflow-reported deletion status (input claim — not a verified truth)."""
    COMPLETE = "COMPLETE"
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    NOT_STARTED = "NOT_STARTED"


class DeletionStatus(str, Enum):
    """Agent-determined deletion status written to output.csv."""
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Phase(str, Enum):
    """Step phase, ordered FINDING → REMEDIATION → VERIFICATION."""
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"

    @classmethod
    def order(cls) -> List["Phase"]:
        return [cls.FINDING, cls.REMEDIATION, cls.VERIFICATION]


class Operation(str, Enum):
    """All allowed step operations, grouped by phase."""
    # Findings
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"
    # Remediation
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"
    # Verification
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"

    @property
    def allowed_phase(self) -> Phase:
        if self in _FINDING_OPS:
            return Phase.FINDING
        if self in _REMEDIATION_OPS:
            return Phase.REMEDIATION
        return Phase.VERIFICATION


class RecordState(str, Enum):
    """All allowed `state` values that appear in output steps."""
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"


class DataCategory(str, Enum):
    """Data categories from deletion_rules.csv."""
    USER_PROFILE = "USER_PROFILE"
    SECONDARY_IDENTIFIER = "SECONDARY_IDENTIFIER"
    SEARCH_INDEX_ENTRY = "SEARCH_INDEX_ENTRY"
    CACHE_ENTRY = "CACHE_ENTRY"
    SUPPORT_MESSAGE = "SUPPORT_MESSAGE"
    SUPPORT_ATTACHMENT = "SUPPORT_ATTACHMENT"
    ANALYTICS_PROFILE = "ANALYTICS_PROFILE"
    PRODUCT_TELEMETRY = "PRODUCT_TELEMETRY"
    USER_EXPORT = "USER_EXPORT"
    MARKETING_PROFILE = "MARKETING_PROFILE"
    EMAIL_DELIVERY_LOG = "EMAIL_DELIVERY_LOG"
    SECURITY_AUDIT_LOG = "SECURITY_AUDIT_LOG"
    LEGAL_HOLD_RECORD = "LEGAL_HOLD_RECORD"
    BACKUP_ARCHIVE = "BACKUP_ARCHIVE"
    ACCOUNT_TOMBSTONE = "ACCOUNT_TOMBSTONE"


class RequiredAction(str, Enum):
    """Required policy actions from deletion_rules.csv."""
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


class SystemId(str, Enum):
    """Known system identifiers, derived from sample_output.csv and evidence."""
    ACCOUNT_SERVICE = "account_service"
    SEARCH_SERVICE = "search_service"
    ANALYTICS_PLATFORM = "analytics_platform"
    SUPPORT_PLATFORM = "support_platform"
    EXPORT_SERVICE = "export_service"
    INTEGRATION_SERVICE = "integration_service"
    BACKUP_SERVICE = "backup_service"
    SECURITY_SERVICE = "security_service"
    LEGAL_SERVICE = "legal_service"
    IDENTITY_SERVICE = "identity_service"
    MARKETING_PLATFORM = "marketing_platform"
    # May appear in EMAIL_DELIVERY_LOG findings
    NOTIFICATION_SERVICE = "notification_service"


class IdentifierType(str, Enum):
    """Types of identifiers used to link evidence to a subject."""
    EMAIL = "email"
    EMAIL_HASH = "email_hash"
    PHONE = "phone"
    USER_ID = "user_id"
    RESOURCE_ID = "resource_id"
    CUSTOMER_REFERENCE = "customer_reference"
    SUBJECT_REFERENCE = "subject_reference"


class EvidenceFormat(str, Enum):
    """Evidence file format categories."""
    SQL = "sql"
    JSON = "json"
    LOG = "log"
    PDF = "pdf"
    IMAGE = "image"
    TXT = "txt"


class LLMConfidence(str, Enum):
    """Confidence levels for LLM-derived facts."""
    HIGH = "high"       # ≥ 0.90
    MEDIUM = "medium"   # 0.70 – 0.89
    LOW = "low"         # < 0.70
    NA = "na"           # fact is not LLM-derived


# ---------------------------------------------------------------------------
# Operation ↔ Phase and Operation ↔ State validation tables
# Sourced verbatim from AGENTS.md §6.4
# ---------------------------------------------------------------------------

_FINDING_OPS: Set[Operation] = {
    Operation.REPORT_REMAINING_RECORD,
    Operation.REPORT_EXPOSED_PII,
    Operation.REPORT_ACTIVE_DATA_FLOW,
    Operation.REPORT_RESTORE_RISK,
}

_REMEDIATION_OPS: Set[Operation] = {
    Operation.DISABLE_DATA_FLOW,
    Operation.BLOCK_RESTORE,
    Operation.DELETE_RECORD,
    Operation.REDACT_RECORD,
    Operation.ANONYMIZE_RECORD,
}

_VERIFICATION_OPS: Set[Operation] = {
    Operation.VERIFY_RECORD_ABSENT,
    Operation.VERIFY_RECORD_PRESENT,
    Operation.VERIFY_RECORD_REDACTED,
    Operation.VERIFY_RECORD_ANONYMIZED,
    Operation.VERIFY_DATA_FLOW_DISABLED,
    Operation.VERIFY_RESTORE_BLOCKED,
}

# Canonical mapping: operation → required state value
OPERATION_STATE_MAP: Dict[Operation, RecordState] = {
    Operation.REPORT_REMAINING_RECORD: RecordState.PRESENT,
    Operation.REPORT_EXPOSED_PII: RecordState.PRESENT,
    Operation.REPORT_ACTIVE_DATA_FLOW: RecordState.ACTIVE,
    Operation.REPORT_RESTORE_RISK: RecordState.ACTIVE,
    Operation.DISABLE_DATA_FLOW: RecordState.DISABLED,
    Operation.BLOCK_RESTORE: RecordState.BLOCKED,
    Operation.DELETE_RECORD: RecordState.ABSENT,
    Operation.REDACT_RECORD: RecordState.REDACTED,
    Operation.ANONYMIZE_RECORD: RecordState.ANONYMIZED,
    Operation.VERIFY_RECORD_ABSENT: RecordState.ABSENT,
    Operation.VERIFY_RECORD_PRESENT: RecordState.PRESENT,
    Operation.VERIFY_RECORD_REDACTED: RecordState.REDACTED,
    Operation.VERIFY_RECORD_ANONYMIZED: RecordState.ANONYMIZED,
    Operation.VERIFY_DATA_FLOW_DISABLED: RecordState.DISABLED,
    Operation.VERIFY_RESTORE_BLOCKED: RecordState.BLOCKED,
}

# Phase → allowed operations
PHASE_OPERATIONS: Dict[Phase, Set[Operation]] = {
    Phase.FINDING: _FINDING_OPS,
    Phase.REMEDIATION: _REMEDIATION_OPS,
    Phase.VERIFICATION: _VERIFICATION_OPS,
}


def validate_operation_state(operation: Operation, state: RecordState) -> None:
    """Raise ValueError if the operation/state pair is not valid."""
    expected = OPERATION_STATE_MAP.get(operation)
    if expected is None:
        raise ValueError(f"Unknown operation: {operation}")
    if state != expected:
        raise ValueError(
            f"Operation {operation!r} requires state {expected!r}, got {state!r}"
        )


def validate_operation_phase(operation: Operation, phase: Phase) -> None:
    """Raise ValueError if the operation does not belong to the given phase."""
    allowed = PHASE_OPERATIONS.get(phase, set())
    if operation not in allowed:
        raise ValueError(
            f"Operation {operation!r} does not belong to phase {phase!r}"
        )


# ---------------------------------------------------------------------------
# Core input models
# ---------------------------------------------------------------------------


class RequestCase(BaseModel):
    """
    One row from deletion_requests.csv or sample_deletion_requests.csv.
    Timestamps are stored both as raw strings and as parsed UTC datetimes.
    """

    case_id: str = Field(..., description="Unique case identifier, e.g. 'case_33'")
    email: str = Field(..., description="Email supplied with the request (current or historical)")
    requested_at_raw: str = Field(..., description="Raw requested_at string from CSV")
    requested_at: datetime = Field(..., description="Parsed timezone-aware UTC datetime")
    reported_status: ReportedStatus
    reported_at_raw: str = Field(..., description="Raw reported_at string from CSV")
    reported_at: datetime = Field(..., description="Parsed timezone-aware UTC datetime")
    audit_at_raw: str = Field(..., description="Raw audit_at string from CSV")
    audit_at: datetime = Field(..., description="Parsed timezone-aware UTC datetime — strict evidence cutoff")
    request_text: str = Field(..., description="Free-text deletion request, possibly multilingual")

    model_config = {"frozen": True}

    @field_validator("case_id")
    @classmethod
    def _valid_case_id(cls, v: str) -> str:
        if not re.match(r"^case_\d+$", v):
            raise ValueError(f"case_id must match 'case_<N>', got {v!r}")
        return v

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("requested_at", "reported_at", "audit_at", mode="before")
    @classmethod
    def _parse_ts(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return _parse_utc(str(v))


class IdentityAlias(BaseModel):
    """
    A single known identifier for a subject, including its provenance.
    Built by identity.py from user_identities.csv + user_audit_log.csv.
    """

    user_id: str = Field(..., description="Stable internal user reference, e.g. 'user_01'")
    identifier_type: IdentifierType
    value: str = Field(..., description="The identifier value (email lowercased, hash hex, phone as-is)")
    is_current: bool = Field(
        True, description="True if this is the current value in user_identities.csv"
    )
    valid_from: Optional[datetime] = Field(
        None, description="Timestamp from user_audit_log when this value became active"
    )
    valid_until: Optional[datetime] = Field(
        None, description="Timestamp from user_audit_log when this value was replaced"
    )
    source_file: str = Field(..., description="CSV path relative to dataset root")
    source_row_id: str = Field(
        ..., description="audit_id from user_audit_log, or user_id for current identity"
    )

    model_config = {"frozen": True}

    @field_validator("value")
    @classmethod
    def _normalise_value(cls, v: str) -> str:
        return v.strip()


class EvidenceRef(BaseModel):
    """
    One row from evidence_files.csv — the manifest entry for a single file.
    """

    file_id: str = Field(..., description="e.g. 'evidence_01'")
    file_path: str = Field(
        ..., description="Path relative to dataset root, e.g. 'evidence/logs/...'  "
    )
    origin: str = Field(..., description="System/service that produced this evidence file")
    captured_at_raw: str
    captured_at: datetime = Field(
        ..., description="When the file was captured — used for audit_at gating"
    )
    format: EvidenceFormat = Field(
        ..., description="Inferred from file extension"
    )

    model_config = {"frozen": True}

    @field_validator("file_id")
    @classmethod
    def _valid_file_id(cls, v: str) -> str:
        if not re.match(r"^evidence_\d+$", v):
            raise ValueError(f"file_id must match 'evidence_<N>', got {v!r}")
        return v

    @field_validator("captured_at", mode="before")
    @classmethod
    def _parse_ts(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return _parse_utc(str(v))

    @field_validator("format", mode="before")
    @classmethod
    def _infer_format(cls, v: Any, info: Any) -> EvidenceFormat:
        if isinstance(v, EvidenceFormat):
            return v
        # If explicitly provided as string, try to coerce
        if isinstance(v, str) and v:
            try:
                return EvidenceFormat(v.lower())
            except ValueError:
                pass
        # Infer from file_path stored in info.data
        fp: str = info.data.get("file_path", "")
        ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        _EXT_MAP = {
            "sql": EvidenceFormat.SQL,
            "json": EvidenceFormat.JSON,
            "log": EvidenceFormat.LOG,
            "pdf": EvidenceFormat.PDF,
            "png": EvidenceFormat.IMAGE,
            "jpg": EvidenceFormat.IMAGE,
            "jpeg": EvidenceFormat.IMAGE,
            "txt": EvidenceFormat.TXT,
        }
        if ext in _EXT_MAP:
            return _EXT_MAP[ext]
        raise ValueError(f"Cannot infer EvidenceFormat from file_path {fp!r}")


class EvidenceFact(BaseModel):
    """
    A single fact extracted from an evidence file, attributed to a subject.

    Provenance fields ensure every fact can be traced back to its source.
    llm_derived=True means this fact came from LLM interpretation (image/PDF).
    """

    file_id: str = Field(..., description="Source evidence_files.csv file_id")
    file_path: str = Field(..., description="Relative path for direct lookup")
    captured_at: datetime = Field(..., description="Evidence capture time (UTC)")
    system_id: str = Field(..., description="Which system this record belongs to")
    resource_id: str = Field(..., description="Stable resource identifier within that system")
    subject_user_id: Optional[str] = Field(
        None, description="Resolved user_id if known"
    )
    subject_email: Optional[str] = Field(
        None, description="Email that matched this record (lowercased)"
    )
    data_category: Optional[DataCategory] = None
    observed_state: RecordState = Field(
        ..., description="The state of this resource as observed in this evidence file"
    )
    raw_value: Optional[str] = Field(
        None,
        description="Verbatim text excerpt from the evidence file (truncated to config max)",
    )
    source_span: Optional[str] = Field(
        None,
        description="SQL table name, JSON path, log line number, or page reference",
    )
    llm_derived: bool = Field(
        False, description="True if this fact was extracted by LLM (image/PDF)"
    )
    llm_confidence: LLMConfidence = Field(
        LLMConfidence.NA,
        description="Confidence when llm_derived=True, otherwise NA",
    )
    needs_review: bool = Field(
        False,
        description="Flagged for manual review when confidence is LOW or evidence is ambiguous",
    )

    model_config = {"frozen": False}  # mutable during construction

    @field_validator("captured_at", mode="before")
    @classmethod
    def _parse_ts(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return _parse_utc(str(v))

    @field_validator("subject_email")
    @classmethod
    def _lower_email(cls, v: Optional[str]) -> Optional[str]:
        return v.lower() if v else v


class ResourceState(BaseModel):
    """
    The reconstructed state of a single resource at audit_at.
    Built by temporal.py from all eligible EvidenceFacts for that resource.
    """

    user_id: str
    system_id: str
    resource_id: str
    data_category: DataCategory
    state_at_audit: RecordState
    best_evidence_file_id: str = Field(
        ..., description="The file_id of the most recent eligible evidence"
    )
    best_evidence_captured_at: datetime
    all_evidence_file_ids: List[str] = Field(default_factory=list)
    has_replica_drift: bool = Field(
        False,
        description="True when a replica has the record but the primary does not, or vice versa",
    )
    needs_review: bool = False


class PolicyRule(BaseModel):
    """
    One row from deletion_rules.csv.
    """

    rule_id: str
    data_category: DataCategory
    condition: str = Field(
        ..., description="Human-readable condition text from deletion_rules.csv"
    )
    required_action: RequiredAction

    model_config = {"frozen": True}


class DataFlowState(BaseModel):
    """
    State of a data-flow connector (integration_service resource).
    Derived from EvidenceFacts for data_flow_<N> resources.
    """

    user_id: str
    resource_id: str = Field(..., description="data_flow_<N>")
    connector_name: Optional[str] = None
    subject_selector: Optional[str] = Field(
        None,
        description="Email or user_id the connector is scoped to",
    )
    enabled: bool = Field(..., description="True = flow is active / problematic")
    best_evidence_file_id: str
    best_evidence_captured_at: datetime


class RestoreRisk(BaseModel):
    """
    A backup archive that poses a restore risk for a subject.
    Derived from EvidenceFacts for backup_<N> resources.
    """

    user_id: str
    resource_id: str = Field(..., description="backup_<N>")
    archive_path: Optional[str] = None
    restore_allowed: bool = Field(
        ..., description="True = backup can be restored (risk); False = already blocked"
    )
    best_evidence_file_id: str
    best_evidence_captured_at: datetime


class AuditFinding(BaseModel):
    """
    A single policy violation or risk discovered during audit.
    Maps to one or more FINDING-phase steps.
    """

    user_id: str
    system_id: str
    resource_id: str
    data_category: DataCategory
    operation: Operation
    state: RecordState
    evidence_file_id: str
    description: str = ""

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _validate_op_state(self) -> "AuditFinding":
        validate_operation_state(self.operation, self.state)
        validate_operation_phase(self.operation, Phase.FINDING)
        return self


class PlannedAction(BaseModel):
    """
    A remediation or verification action to be taken.
    Maps to REMEDIATION or VERIFICATION phase steps.
    evidence_id is always empty for REMEDIATION and INCOMPLETE VERIFICATION.
    """

    phase: Phase
    system_id: str
    resource_id: str
    operation: Operation
    state: RecordState
    evidence_id: str = Field(
        "",
        description="Non-empty only for COMPLETE VERIFICATION steps",
    )

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _validate(self) -> "PlannedAction":
        validate_operation_state(self.operation, self.state)
        validate_operation_phase(self.operation, self.phase)
        if self.phase == Phase.FINDING:
            raise ValueError(
                "PlannedAction cannot have phase=FINDING; use AuditFinding instead"
            )
        if self.phase == Phase.REMEDIATION and self.evidence_id:
            raise ValueError(
                "REMEDIATION steps must always have evidence_id=''"
            )
        return self


class AuditStep(BaseModel):
    """
    A fully-formed output step as written to steps_json.
    Fields exactly match the benchmark output schema.
    """

    step_no: int = Field(..., ge=1)
    phase: Phase
    system_id: str
    resource_id: str
    operation: Operation
    state: RecordState
    evidence_id: str

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _validate(self) -> "AuditStep":
        validate_operation_state(self.operation, self.state)
        validate_operation_phase(self.operation, self.phase)
        return self

    def to_output_dict(self) -> Dict[str, Any]:
        """Serialize to the exact dict the benchmark grader expects."""
        return {
            "step_no": self.step_no,
            "phase": self.phase.value,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation.value,
            "state": self.state.value,
            "evidence_id": self.evidence_id,
        }


class CaseResult(BaseModel):
    """
    The complete audit result for a single case.
    Produced by audit_engine.py; consumed by output_writer.py.
    """

    case_id: str
    deletion_status: DeletionStatus
    steps: List[AuditStep] = Field(default_factory=list)
    # Provenance / debug fields (not written to output.csv)
    user_id: Optional[str] = None
    resolved_emails: List[str] = Field(default_factory=list)
    findings: List[AuditFinding] = Field(default_factory=list)
    planned_actions: List[PlannedAction] = Field(default_factory=list)
    evidence_file_ids_used: List[str] = Field(default_factory=list)
    request_authorized: Optional[bool] = None
    authorization_reason: str = ""
    authorization_llm_confidence: LLMConfidence = LLMConfidence.NA
    needs_review: bool = False
    error: Optional[str] = None

    model_config = {"frozen": False}

    @model_validator(mode="after")
    def _validate_steps(self) -> "CaseResult":
        self._check_step_nos()
        self._check_phase_order()
        return self

    def _check_step_nos(self) -> None:
        for i, step in enumerate(self.steps, start=1):
            if step.step_no != i:
                raise ValueError(
                    f"[{self.case_id}] Step numbering broken: "
                    f"step at position {i} has step_no={step.step_no}"
                )

    def _check_phase_order(self) -> None:
        """Phases must appear in FINDING → REMEDIATION → VERIFICATION order (no back-tracking)."""
        phase_order = {p: i for i, p in enumerate(Phase.order())}
        last_idx = -1
        for step in self.steps:
            idx = phase_order[step.phase]
            if idx < last_idx:
                raise ValueError(
                    f"[{self.case_id}] Phase order violated at step {step.step_no}: "
                    f"{step.phase} after a later phase"
                )
            last_idx = idx

    @property
    def not_applicable(self) -> bool:
        return self.deletion_status == DeletionStatus.NOT_APPLICABLE

    def to_output_row(self) -> Dict[str, Any]:
        """Produce the exact row dict for output.csv."""
        import json as _json
        steps_list = [s.to_output_dict() for s in self.steps]
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status.value,
            "steps_json": _json.dumps(steps_list, separators=(",", ":"), ensure_ascii=False),
        }


class RunUsage(BaseModel):
    """
    Token and cost accounting for a full run.
    Written to evaluation/usage_report.md.
    """

    model_config = {"protected_namespaces": ()}

    model_provider: str = ""
    model_name: str = ""
    total_cases: int = 0
    llm_calls: int = 0
    measured_calls: int = 0
    unknown_token_calls: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    retries: int = 0
    failures: int = 0
    call_records: List[Dict[str, Any]] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    avg_tokens_per_case: float = 0.0
    estimated_cost_usd: float = 0.0
    avg_cost_per_case_usd: float = 0.0
    per_model_breakdown: List[Dict[str, Any]] = Field(default_factory=list)

    def add_call(
        self,
        input_toks: Optional[int],
        output_toks: Optional[int],
        cost_usd: float = 0.0,
        model: str = "",
        provider: str = "",
        success: bool = True,
    ) -> None:
        self.llm_calls += 1
        if input_toks is None or output_toks is None:
            self.unknown_token_calls += 1
        else:
            self.measured_calls += 1
            self.input_tokens += input_toks
            self.output_tokens += output_toks
            self.total_tokens += input_toks + output_toks
        self.estimated_cost_usd += cost_usd
        if not success:
            self.failures += 1
        if provider:
            self.model_provider = provider
        if model:
            self.model_name = model
        if self.total_cases:
            self.avg_tokens_per_case = self.total_tokens / self.total_cases
            self.avg_cost_per_case_usd = self.estimated_cost_usd / self.total_cases
