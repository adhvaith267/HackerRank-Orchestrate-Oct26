"""
main.py — Ghost Data Still Exists deletion-audit agent entry point.

Status selection and step generation are driven entirely by AuditAnalysis;
the model never authors final steps directly.

Usage
-----
    python3 code/main.py

Reads from:
    dataset/deletion_requests.csv
    dataset/user_identities.csv
    dataset/user_audit_log.csv
    dataset/system_activity.csv
    dataset/deletion_rules.csv
    dataset/evidence_files.csv
    dataset/evidence/          (evidence files)

Writes:
    output.csv  (at repository root)

Environment variables (optional, for LLM-assisted evidence parsing):
    ANTHROPIC_API_KEY   — if using Claude for image/PDF extraction
    OPENAI_API_KEY      — if using OpenAI for image/PDF extraction

Both keys are read from .env if present.  Set neither to run in
deterministic-only mode (no LLM calls, images/PDFs skipped).
"""

from __future__ import annotations

import csv
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Bootstrap: make the ghost_audit package importable
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PKG_SRC = _REPO_ROOT / "code" / "ghost-data-audit" / "src"
if str(_PKG_SRC) not in sys.path:
    sys.path.insert(0, str(_PKG_SRC))

# ---------------------------------------------------------------------------
# Load .env if present (never required; secrets stay out of source)
# ---------------------------------------------------------------------------

try:
    from dotenv import load_dotenv  # type: ignore[import]

    load_dotenv(_REPO_ROOT / ".env", override=False)
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Imports from ghost_audit
# ---------------------------------------------------------------------------

from ghost_audit.audit_core import (
    AuditAnalysis,
    AuditCore,
    DataFlowRecord,
    FlowStatus,
    PolicyEngine,
    ResourceInventoryState,
    RestoreRiskRecord,
)
from ghost_audit.schemas import (
    AuditFinding,
    AuditStep,
    CaseResult,
    DataCategory,
    DataFlowState,
    DeletionStatus,
    EvidenceFact,
    Operation,
    Phase,
    PlannedAction,
    PolicyRule,
    RecordState,
    RequiredAction,
    ResourceState,
    RestoreRisk,
)
from ghost_audit.step_builder import build_steps

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("main")

# ---------------------------------------------------------------------------
# Dataset paths
# ---------------------------------------------------------------------------

DATASET = _REPO_ROOT / "dataset"
REQUESTS_CSV = DATASET / "deletion_requests.csv"
RULES_CSV = DATASET / "deletion_rules.csv"
OUTPUT_CSV = _REPO_ROOT / "output.csv"

_UTC = timezone.utc

# ===========================================================================
# Step ordering constants (canonical from AGENTS.md §6.4 + sample_output.csv)
# ===========================================================================

_FINDING_OP_ORDER: Dict[Operation, int] = {
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

# Canonical state for each operation (from AGENTS.md §6.4)
_OPERATION_STATE: Dict[Operation, RecordState] = {
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

# RequiredAction → remediation Operation
_ACTION_TO_REMEDIATION_OP: Dict[RequiredAction, Optional[Operation]] = {
    RequiredAction.DELETE: Operation.DELETE_RECORD,
    RequiredAction.REDACT: Operation.REDACT_RECORD,
    RequiredAction.ANONYMIZE: Operation.ANONYMIZE_RECORD,
    RequiredAction.RETAIN: None,
}

# RequiredAction → verification Operation
_ACTION_TO_VERIFY_OP: Dict[RequiredAction, Operation] = {
    RequiredAction.DELETE: Operation.VERIFY_RECORD_ABSENT,
    RequiredAction.REDACT: Operation.VERIFY_RECORD_REDACTED,
    RequiredAction.ANONYMIZE: Operation.VERIFY_RECORD_ANONYMIZED,
    RequiredAction.RETAIN: Operation.VERIFY_RECORD_PRESENT,
}

# RecordState → verification Operation
_STATE_TO_VERIFY_OP: Dict[RecordState, Operation] = {
    RecordState.ABSENT: Operation.VERIFY_RECORD_ABSENT,
    RecordState.REDACTED: Operation.VERIFY_RECORD_REDACTED,
    RecordState.ANONYMIZED: Operation.VERIFY_RECORD_ANONYMIZED,
    RecordState.PRESENT: Operation.VERIFY_RECORD_PRESENT,
    RecordState.DISABLED: Operation.VERIFY_DATA_FLOW_DISABLED,
    RecordState.BLOCKED: Operation.VERIFY_RESTORE_BLOCKED,
}


# ===========================================================================
# Status selection (§6.5 rules, strictly from AuditAnalysis)
# ===========================================================================


def select_deletion_status(
    analysis: AuditAnalysis,
    request_authorized: bool,
) -> DeletionStatus:
    """
    Determine deletion_status strictly from AuditAnalysis.

    Rules (from AGENTS.md §6.5 and task prompt):
    1. NOT_APPLICABLE if request_text does not authorize deletion.
    2. COMPLETE only when all violations, active flows, and active restore
       risks are absent, AND evidence gaps do not prevent that conclusion.
    3. INCOMPLETE otherwise.

    reported_status is intentionally NOT consulted here.
    """
    if not request_authorized:
        return DeletionStatus.NOT_APPLICABLE

    # Any evidence gap means we cannot claim COMPLETE
    # (insufficient evidence → cannot prove a required criterion)
    if analysis.evidence_gaps or analysis.temporal_conflicts:
        return DeletionStatus.INCOMPLETE

    if analysis.is_complete:
        return DeletionStatus.COMPLETE

    return DeletionStatus.INCOMPLETE


# ===========================================================================
# Step generation from AuditAnalysis
# ===========================================================================

def _sort_key_finding(step_tuple: Tuple[Operation, str, str]) -> Tuple:
    op, sys_id, res_id = step_tuple
    return (_FINDING_OP_ORDER.get(op, 99), sys_id, res_id)


def _sort_key_remediation(step_tuple: Tuple[Operation, str, str]) -> Tuple:
    op, sys_id, res_id = step_tuple
    return (_REMEDIATION_OP_ORDER.get(op, 99), sys_id, res_id)


def _sort_key_verification(step_tuple: Tuple[Operation, str, str]) -> Tuple:
    op, sys_id, res_id = step_tuple
    return (_VERIFICATION_OP_ORDER.get(op, 99), sys_id, res_id)


def _required_action_from_entry(entry: Any) -> Optional[RequiredAction]:
    """Return the policy treatment already recorded on an analysis entry.

    AuditAnalysis is intentionally the only input to planning.  InventoryEntry
    carries the typed category, while its policy evaluation is represented by
    the analysis' compliant/violation collections.  This helper is only used
    for compliant entries and derives the treatment from the attached rule
    when available; it never reads raw evidence or request metadata.
    """
    # AuditAnalysis.compliant_resources are InventoryEntry objects.  The core
    # stores the evaluated treatment on the matching PolicyViolation, so a
    # compliant entry has no violation.  PolicyEngine is therefore not needed
    # for the common path; the category's canonical mapping is stable.
    return getattr(entry, "required_action", None)


def _dedupe_candidates(candidates: List[Tuple]) -> List[Tuple]:
    """Deduplicate only identical output steps, preserving first provenance."""
    result: List[Tuple] = []
    seen: Set[Tuple[Any, ...]] = set()
    for candidate in candidates:
        op, sys_id, res_id = candidate[:3]
        state = _OPERATION_STATE[op]
        key = (op, sys_id, res_id, state)
        if key not in seen:
            seen.add(key)
            result.append(candidate)
    return result


def generate_steps_from_analysis(
    analysis: AuditAnalysis,
    status: DeletionStatus,
    policy_engine: Optional[PolicyEngine] = None,
) -> List[AuditStep]:
    """
    Build the complete ordered steps_json from AuditAnalysis.

    This function is the single place where steps are assembled;
    the model never writes step dicts directly.

    For COMPLETE:   only evidence-backed verification steps (real evidence_ids).
    For INCOMPLETE: FINDING (cite evidence) + REMEDIATION (evidence_id='')
                    + VERIFICATION (evidence_id='').
    For NOT_APPLICABLE: [].
    """
    if status == DeletionStatus.NOT_APPLICABLE:
        return []

    # ``policy_engine`` remains an optional compatibility argument for callers
    # of the original entry point.  It is intentionally not consulted: once
    # AuditCore has produced AuditAnalysis, the model/raw dataset cannot alter
    # the status, actions, identifiers, or ordering of the final steps.
    if status == DeletionStatus.COMPLETE:
        return _build_complete_steps(analysis)
    return _build_incomplete_steps(analysis)


# ---------------------------------------------------------------------------
# COMPLETE path
# ---------------------------------------------------------------------------

def _build_complete_steps(
    analysis: AuditAnalysis,
) -> List[AuditStep]:
    """
    COMPLETE: emit only verification steps backed by real evidence_id.

    Each compliant inventory entry gets a verification step.
    Retained records get VERIFY_RECORD_PRESENT.
    Compliant flows get VERIFY_DATA_FLOW_DISABLED.
    Blocked restores get VERIFY_RESTORE_BLOCKED.
    """
    # (operation, system_id, resource_id, evidence_id) tuples
    candidates: List[Tuple[Operation, str, str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    # Compliant inventory entries
    for entry in analysis.compliant_resources:
        key = (entry.system_id, entry.resource_id)
        if key in seen:
            continue
        seen.add(key)

        if entry.data_category is None:
            continue
        action = _required_action_from_entry(entry)
        if action is None:
            continue
        op = _ACTION_TO_VERIFY_OP.get(action)
        if op is None:
            continue

        evidence_id = entry.best_source_id
        if not evidence_id:
            # Cannot emit a COMPLETE verification step without evidence
            continue
        candidates.append((op, entry.system_id, entry.resource_id, evidence_id))

    # Retained records (VERIFY_RECORD_PRESENT)
    for ret in analysis.retained_records:
        key = (ret.system_id, ret.resource_id)
        if key in seen:
            continue
        seen.add(key)
        if not ret.evidence_source_id:
            continue
        candidates.append((
            Operation.VERIFY_RECORD_PRESENT,
            ret.system_id,
            ret.resource_id,
            ret.evidence_source_id,
        ))

    # Historical flows (disabled) → VERIFY_DATA_FLOW_DISABLED
    # These come from the full flow list minus active ones
    for entry in analysis.inventory:
        if not entry.resource_id.startswith("data_flow"):
            continue
        if entry.state not in (
            ResourceInventoryState.ABSENT_CONFIRMED,
            # DISABLED maps to ABSENT_CONFIRMED via _map_record_state_to_inv
        ):
            continue
        key = ("integration_service", entry.resource_id)
        if key in seen:
            continue
        seen.add(key)
        if not entry.best_source_id:
            continue
        candidates.append((
            Operation.VERIFY_DATA_FLOW_DISABLED,
            "integration_service",
            entry.resource_id,
            entry.best_source_id,
        ))

    # Blocked restores → VERIFY_RESTORE_BLOCKED
    for rr in analysis.restore_risks:
        if not rr.restore_blocked:
            continue
        key = ("backup_service", rr.resource_id)
        if key in seen or not rr.evidence_source_id:
            continue
        seen.add(key)
        candidates.append((
            Operation.VERIFY_RESTORE_BLOCKED,
            "backup_service",
            rr.resource_id,
            rr.evidence_source_id,
        ))

    # Sort by verification order, then system_id, resource_id
    candidates = _dedupe_candidates(candidates)
    candidates.sort(key=lambda t: _sort_key_verification((t[0], t[1], t[2])))

    # Build AuditStep list
    steps: List[AuditStep] = []
    for i, (op, sys_id, res_id, ev_id) in enumerate(candidates, start=1):
        steps.append(AuditStep(
            step_no=i,
            phase=Phase.VERIFICATION,
            system_id=sys_id,
            resource_id=res_id,
            operation=op,
            state=_OPERATION_STATE[op],
            evidence_id=ev_id,
        ))
    return steps


# ---------------------------------------------------------------------------
# INCOMPLETE path
# ---------------------------------------------------------------------------

def _build_incomplete_steps(
    analysis: AuditAnalysis,
) -> List[AuditStep]:
    """
    INCOMPLETE: FINDING (cite evidence) + REMEDIATION + VERIFICATION
    (remediation and verification evidence_id always '').
    """
    # ---- FINDING ----
    finding_tuples: List[Tuple[Operation, str, str, str]] = []  # op, sys, res, ev_id
    seen_findings: Set[Tuple[Operation, str, str, RecordState]] = set()

    # Violations → finding operations
    for v in analysis.violations:
        op = _violation_to_finding_op(v)
        if op is None:
            continue
        key = (op, v.system_id, v.resource_id, _OPERATION_STATE[op])
        if key in seen_findings:
            continue
        seen_findings.add(key)
        ev_id = v.evidence_source_id or ""
        finding_tuples.append((op, v.system_id, v.resource_id, ev_id))

    # Active flows → REPORT_ACTIVE_DATA_FLOW
    for flow in analysis.active_flows:
        sys_id = "integration_service"
        key = (Operation.REPORT_ACTIVE_DATA_FLOW, sys_id, flow.resource_id, RecordState.ACTIVE)
        if key in seen_findings:
            continue
        seen_findings.add(key)
        finding_tuples.append((
            Operation.REPORT_ACTIVE_DATA_FLOW,
            sys_id,
            flow.resource_id,
            flow.evidence_source_id or "",
        ))

    # Active restore risks → REPORT_RESTORE_RISK
    for rr in analysis.restore_risks:
        if not rr.is_active_risk:
            continue
        key = (Operation.REPORT_RESTORE_RISK, "backup_service", rr.resource_id, RecordState.ACTIVE)
        if key in seen_findings:
            continue
        seen_findings.add(key)
        finding_tuples.append((
            Operation.REPORT_RESTORE_RISK,
            "backup_service",
            rr.resource_id,
            rr.evidence_source_id or "",
        ))

    finding_tuples.sort(key=lambda t: _sort_key_finding((t[0], t[1], t[2])))

    # ---- REMEDIATION ----
    remediation_tuples: List[Tuple[Operation, str, str]] = []  # op, sys, res

    for (f_op, sys_id, res_id, _ev) in finding_tuples:
        r_op = _finding_to_remediation_op(f_op, sys_id, res_id, analysis)
        if r_op is None:
            continue
        remediation_tuples.append((r_op, sys_id, res_id))

    remediation_tuples.sort(key=lambda t: _sort_key_remediation((t[0], t[1], t[2])))

    # ---- VERIFICATION ----
    verification_tuples: List[Tuple[Operation, str, str]] = []  # op, sys, res

    # All resources that need post-remediation verification
    # Include remediated resources
    for (r_op, sys_id, res_id) in remediation_tuples:
        target_state = _OPERATION_STATE[r_op]
        v_op = _STATE_TO_VERIFY_OP.get(target_state)
        if v_op is not None:
            verification_tuples.append((v_op, sys_id, res_id))

    # Also include already-compliant resources (they still need verification)
    for entry in analysis.compliant_resources:
        if entry.resource_id.startswith("data_flow") or entry.resource_id.startswith("backup"):
            continue
        if entry.data_category is None:
            continue
        action = _required_action_from_entry(entry)
        if action is None:
            continue
        v_op = _ACTION_TO_VERIFY_OP.get(action)
        if v_op is None:
            continue
        verification_tuples.append((v_op, entry.system_id, entry.resource_id))

    # Retained records (VERIFY_RECORD_PRESENT)
    for ret in analysis.retained_records:
        verification_tuples.append((
            Operation.VERIFY_RECORD_PRESENT,
            ret.system_id,
            ret.resource_id,
        ))

    verification_tuples = _dedupe_candidates(verification_tuples)
    verification_tuples.sort(key=lambda t: _sort_key_verification((t[0], t[1], t[2])))

    # ---- ASSEMBLE ----
    steps: List[AuditStep] = []
    step_no = 1

    for (op, sys_id, res_id, ev_id) in finding_tuples:
        steps.append(AuditStep(
            step_no=step_no,
            phase=Phase.FINDING,
            system_id=sys_id,
            resource_id=res_id,
            operation=op,
            state=_OPERATION_STATE[op],
            evidence_id=ev_id,
        ))
        step_no += 1

    for (op, sys_id, res_id) in remediation_tuples:
        steps.append(AuditStep(
            step_no=step_no,
            phase=Phase.REMEDIATION,
            system_id=sys_id,
            resource_id=res_id,
            operation=op,
            state=_OPERATION_STATE[op],
            evidence_id="",
        ))
        step_no += 1

    for (op, sys_id, res_id) in verification_tuples:
        steps.append(AuditStep(
            step_no=step_no,
            phase=Phase.VERIFICATION,
            system_id=sys_id,
            resource_id=res_id,
            operation=op,
            state=_OPERATION_STATE[op],
            evidence_id="",
        ))
        step_no += 1

    return steps


# ---------------------------------------------------------------------------
# Helper: violation → finding operation
# ---------------------------------------------------------------------------

def _violation_to_finding_op(violation: Any) -> Optional[Operation]:
    """
    Map a PolicyViolation to the appropriate finding operation.

    REPORT_REMAINING_RECORD — record that should be deleted still exists.
    REPORT_EXPOSED_PII      — record that should be redacted/anonymized still
                              exposes identifiers.
    """
    from ghost_audit.audit_core import PolicyViolation

    if not isinstance(violation, PolicyViolation):
        return None

    rule = violation.rule
    if rule.required_action == RequiredAction.DELETE:
        return Operation.REPORT_REMAINING_RECORD
    if rule.required_action in (RequiredAction.REDACT, RequiredAction.ANONYMIZE):
        return Operation.REPORT_EXPOSED_PII
    return None


# ---------------------------------------------------------------------------
# Helper: finding operation → remediation operation
# ---------------------------------------------------------------------------

def _finding_to_remediation_op(
    finding_op: Operation,
    sys_id: str,
    res_id: str,
    analysis: AuditAnalysis,
) -> Optional[Operation]:
    """Map a finding operation to the corresponding remediation operation."""
    if finding_op == Operation.REPORT_ACTIVE_DATA_FLOW:
        return Operation.DISABLE_DATA_FLOW
    if finding_op == Operation.REPORT_RESTORE_RISK:
        return Operation.BLOCK_RESTORE
    # For record findings, use the exact policy violation in AuditAnalysis.
    # This prevents a second policy lookup from changing the model's analysis.
    for violation in analysis.violations:
        if violation.system_id == sys_id and violation.resource_id == res_id:
            return _ACTION_TO_REMEDIATION_OP.get(violation.rule.required_action)

    # Defensive fallback for a hand-built analysis with no violation object.
    for entry in analysis.inventory:
        if entry.system_id == sys_id and entry.resource_id == res_id:
            action = _required_action_from_entry(entry)
            return _ACTION_TO_REMEDIATION_OP.get(action) if action else None
    return Operation.DELETE_RECORD


# ===========================================================================
# CSV serialization
# ===========================================================================

def serialize_steps_json(steps: List[AuditStep]) -> str:
    """
    Serialize steps to a compact JSON string.

    Key order within each step object matches the benchmark's canonical
    field order (step_no, phase, system_id, resource_id, operation, state,
    evidence_id).  The grader ignores key order, but deterministic output
    aids debugging.
    """
    return json.dumps(
        [s.to_output_dict() for s in steps],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def write_output_csv(results: List[CaseResult], output_path: Path) -> None:
    """
    Write CaseResult list to output.csv.

    Rows are sorted by numeric case_id.  The CSV is UTF-8 with LF line endings
    and uses standard quoting (fields containing commas/newlines are quoted).
    """
    sorted_results = sorted(
        results,
        key=lambda r: int(r.case_id.split("_")[1]),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["case_id", "deletion_status", "steps_json"],
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        writer.writeheader()
        for result in sorted_results:
            writer.writerow(result.to_output_row())
    logger.info("Wrote %d rows to %s", len(sorted_results), output_path)


# ===========================================================================
# Main pipeline
# ===========================================================================

def _load_requests(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _parse_audit_at(raw: str) -> datetime:
    raw = raw.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_UTC)
    return dt.astimezone(_UTC)


def _is_deletion_request(request_text: str) -> bool:
    """
    Rule §6.5: determine whether request_text authorizes deletion.

    A request is valid if it explicitly requests erasure/deletion of
    personal data.  Requests for access, correction, export, marketing
    opt-out, or other non-deletion actions return False.

    This is a deterministic heuristic; LLM classification is applied
    by the audit_engine when running with a model key.
    """
    text = request_text.strip().lower()
    if not text:
        return False

    # Strong deletion indicators (multilingual)
    deletion_keywords = [
        # English
        "delete", "erase", "erasure", "remove", "right to be forgotten",
        "deletion request", "gdpr deletion", "please delete", "delete my",
        "right of erasure", "data deletion", "account deletion",
        "forget me", "remove my data", "remove my account",
        "wipe my data", "purge my data", "permanently delete",
        # Spanish
        "eliminar", "borrar", "derecho al olvido", "eliminar mis datos",
        # French
        "effacer", "supprimer", "suppression", "droit à l'oubli",
        # German
        "löschen", "löschung", "datenlöschung",
        # Portuguese
        "excluir", "apagar",
        # Italian
        "cancellare", "eliminare",
        # Dutch
        "verwijder", "verwijdering",
        # Arabic
        "حذف", "إزالة",
        # Hindi
        "हटाएं", "मिटाएं",
    ]

    # Non-deletion indicators that veto deletion keywords
    # (e.g., "delete my marketing emails" is opt-out, not data deletion)
    non_deletion_veto_phrases = [
        "unsubscribe",
        "opt out",
        "opt-out",
        "stop sending",
        "access my data",
        "copy of my data",
        "data portability",
        "export my data",
        "correct my",
        "update my",
        "change my",
        "password reset",
        "account recovery",
    ]

    # Check for non-deletion veto phrases first
    for phrase in non_deletion_veto_phrases:
        if phrase in text:
            return False

    # Check for deletion keywords
    for kw in deletion_keywords:
        if kw in text:
            return True

    return False


def run_pipeline(
    requests_csv: Path = REQUESTS_CSV,
    rules_csv: Path = RULES_CSV,
    output_csv: Path = OUTPUT_CSV,
    evidence_facts_by_case: Optional[Dict[str, List[EvidenceFact]]] = None,
    analysis_by_case: Optional[Dict[str, AuditAnalysis]] = None,
) -> List[CaseResult]:
    """
    Run the full audit pipeline.

    Parameters
    ----------
    requests_csv:
        Path to deletion_requests.csv (or sample_deletion_requests.csv for testing).
    rules_csv:
        Path to deletion_rules.csv.
    output_csv:
        Destination path for output.csv.
    evidence_facts_by_case:
        Optional pre-built evidence facts keyed by case_id.
        If None, evidence ingestion is performed by the audit_engine module.
    analysis_by_case:
        Optional pre-built AuditAnalysis keyed by case_id.
        If provided, status selection and step generation use these directly
        without re-running evidence ingestion.

    Returns
    -------
    List[CaseResult] — one per case, sorted by case_id.
    """
    # Load policy rules
    policy_engine = PolicyEngine.from_csv(rules_csv)
    logger.info("Loaded policy rules from %s", rules_csv)

    # Build policy_rules dict for step_builder compatibility
    policy_rules: Dict[DataCategory, PolicyRule] = {}
    for rule in policy_engine._all_rules:
        policy_rules[rule.data_category] = PolicyRule(
            rule_id=rule.rule_id,
            data_category=rule.data_category,
            condition=rule.condition,
            required_action=rule.required_action,
        )

    # Load requests
    requests = _load_requests(requests_csv)
    logger.info("Loaded %d requests from %s", len(requests), requests_csv)

    results: List[CaseResult] = []

    for row in requests:
        case_id = row["case_id"]
        request_text = row.get("request_text", "")
        audit_at_raw = row.get("audit_at", "")

        try:
            audit_at = _parse_audit_at(audit_at_raw)
        except Exception as exc:
            logger.error("Cannot parse audit_at for %s: %s", case_id, exc)
            results.append(CaseResult(
                case_id=case_id,
                deletion_status=DeletionStatus.NOT_APPLICABLE,
                steps=[],
                error=f"parse_error:{exc}",
            ))
            continue

        # Determine if request authorizes deletion
        request_authorized = _is_deletion_request(request_text)

        # If pre-built analysis is available, use it
        if analysis_by_case is not None and case_id in analysis_by_case:
            analysis = analysis_by_case[case_id]
        else:
            # Build a minimal AuditAnalysis from evidence_facts if provided,
            # otherwise create an empty one (no evidence → all UNKNOWN → INCOMPLETE)
            facts = (evidence_facts_by_case or {}).get(case_id, [])
            audit_core = AuditCore(policy_engine)
            analysis = audit_core.analyze_case(
                case_id=case_id,
                user_id=row.get("user_id"),
                audit_at=audit_at,
                evidence_facts=facts,
            )

        # Select status
        status = select_deletion_status(analysis, request_authorized)

        # Generate steps from analysis
        steps = generate_steps_from_analysis(analysis, status, policy_engine)

        result = CaseResult(
            case_id=case_id,
            deletion_status=status,
            steps=steps,
            request_authorized=request_authorized,
        )
        results.append(result)

    # Write output
    write_output_csv(results, output_csv)

    return results


def main() -> None:
    """Entry point."""
    logger.info("Starting Ghost Data Still Exists audit pipeline")

    # Try to import and use the full audit_engine with evidence ingestion
    try:
        from ghost_audit.audit_engine import AuditEngine  # type: ignore[import]
        from ghost_audit.config import Config  # type: ignore[import]

        config_path = _REPO_ROOT / "code" / "ghost-data-audit" / "config.example.yaml"
        config = Config.from_yaml(config_path) if config_path.exists() else Config()

        engine = AuditEngine(config=config, dataset_root=DATASET)
        results = engine.run_all(output_path=OUTPUT_CSV)
        logger.info(
            "AuditEngine completed: %d results written to %s",
            len(results),
            OUTPUT_CSV,
        )
    except Exception as exc:
        logger.warning(
            "AuditEngine not available or failed (%s); "
            "falling back to deterministic-only pipeline",
            exc,
        )
        results = run_pipeline()

    logger.info("Done. Output written to %s", OUTPUT_CSV)


if __name__ == "__main__":
    main()
