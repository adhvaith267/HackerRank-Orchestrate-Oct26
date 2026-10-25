"""
audit_core.py — Deterministic audit core for ghost-data-audit.

This module is the single source of truth for audit decisions. It is
deliberately free of LLM calls; all decisions are derived from typed
evidence facts and policy rules parsed from the actual dataset.

Public API
----------
ResourceInventoryState   — internal sufficiency enum (ABSENT_CONFIRMED etc.)
InventoryEntry           — one resource's tracked state with full provenance
ResourceInventory        — manages all entries; exposes conflict detection

ActivityEvent            — typed wrapper for a system_activity.csv row
ConflictKind             — enum for temporal conflict categories
ConflictRecord           — structured conflict with citations
TemporalEventProcessor   — orders events, applies conflict rules, derives states

TypedPolicyRule          — strongly-typed rule from deletion_rules.csv
PolicyEngine             — parses CSV, evaluates required treatment

DataFlowDirection        — source → destination directed model
DataFlowRecord           — evidence-backed active/historical flow
RestoreRiskRecord        — evidence-backed backup/restore risk
DataFlowAnalyzer         — separates active from historical flows

AuditAnalysis            — complete structured result per case
AuditCore                — orchestrates all components; entry point
"""

from __future__ import annotations

import csv
import hashlib
import logging
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ghost_audit.schemas import (
    DataCategory,
    EvidenceFact,
    Operation,
    RecordState,
    RequiredAction,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Documented timezone rule for naive timestamps
# ---------------------------------------------------------------------------
# DATA_DISCOVERY.md §2.2 documents all CSV timestamps as "ISO-8601 UTC"
# (format: 2026-07-16T08:00:00Z).  Any timestamp without a zone offset that
# appears in participant-facing files is treated as UTC.  This choice is
# recorded here and must not be changed silently.
_DOCUMENTED_TZ = timezone.utc

_UTC = timezone.utc


def _ensure_utc(dt: datetime) -> datetime:
    """Attach UTC to a naive datetime using the dataset-documented rule."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_DOCUMENTED_TZ)
    return dt.astimezone(_UTC)


def _parse_ts(raw: str) -> datetime:
    raw = raw.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    return _ensure_utc(dt)


# ===========================================================================
# A. Resource Inventory
# ===========================================================================


class ResourceInventoryState(str, Enum):
    """
    Internal evidence-sufficiency states.

    These are more granular than the output RecordState and distinguish
    evidence quality.  They are mapped to output states only when justified.

    ABSENT_CONFIRMED     — authoritative source proves the record does not exist.
    PRESENT              — at least one source places the record in scope.
    REDACTED_CONFIRMED   — authoritative source proves required fields are removed.
    ANONYMIZED_CONFIRMED — authoritative source proves unlinking is irreversible.
    UNKNOWN              — no evidence covers this resource.
    CONFLICTED           — multiple authoritative sources disagree on the state.
    """
    ABSENT_CONFIRMED = "ABSENT_CONFIRMED"
    PRESENT = "PRESENT"
    REDACTED_CONFIRMED = "REDACTED_CONFIRMED"
    ANONYMIZED_CONFIRMED = "ANONYMIZED_CONFIRMED"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"

    def to_record_state(self) -> Optional[RecordState]:
        """Map to an output RecordState.  Returns None for UNKNOWN/CONFLICTED."""
        _MAP = {
            ResourceInventoryState.ABSENT_CONFIRMED: RecordState.ABSENT,
            ResourceInventoryState.PRESENT: RecordState.PRESENT,
            ResourceInventoryState.REDACTED_CONFIRMED: RecordState.REDACTED,
            ResourceInventoryState.ANONYMIZED_CONFIRMED: RecordState.ANONYMIZED,
        }
        return _MAP.get(self)


@dataclass
class StateTransition:
    """One step in a resource's state history."""
    timestamp: datetime          # event or capture time
    from_state: ResourceInventoryState
    to_state: ResourceInventoryState
    source_id: str               # file_id, activity_id, or audit_id
    reason: str                  # short machine-readable reason


@dataclass
class InventoryEntry:
    """
    Full tracked record for one (system_id, resource_id) pair.

    The state field is the *current* state as of the latest eligible evidence.
    history records every transition with its citation.
    """
    system_id: str
    resource_id: str
    data_category: Optional[DataCategory]
    subject_user_id: Optional[str]
    required_action: Optional[RequiredAction] = None
    state: ResourceInventoryState = ResourceInventoryState.UNKNOWN
    best_source_id: str = ""          # file_id or activity_id of best evidence
    best_captured_at: Optional[datetime] = None
    history: List[StateTransition] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)  # source_ids that conflict
    all_source_ids: List[str] = field(default_factory=list)

    def record_transition(
        self,
        new_state: ResourceInventoryState,
        source_id: str,
        captured_at: datetime,
        reason: str,
    ) -> None:
        """Apply a new observation, updating state and recording the transition."""
        old_state = self.state
        self.history.append(StateTransition(
            timestamp=captured_at,
            from_state=old_state,
            to_state=new_state,
            source_id=source_id,
            reason=reason,
        ))
        self.state = new_state
        if source_id not in self.all_source_ids:
            self.all_source_ids.append(source_id)
        # Keep best evidence as most recent
        if self.best_captured_at is None or captured_at > self.best_captured_at:
            self.best_source_id = source_id
            self.best_captured_at = captured_at

    def mark_conflicted(self, conflicting_source_id: str, reason: str) -> None:
        """Downgrade to CONFLICTED state and record the conflicting source."""
        if conflicting_source_id not in self.conflicts:
            self.conflicts.append(conflicting_source_id)
        if self.state not in (ResourceInventoryState.CONFLICTED,):
            self.history.append(StateTransition(
                timestamp=self.best_captured_at or datetime.now(_UTC),
                from_state=self.state,
                to_state=ResourceInventoryState.CONFLICTED,
                source_id=conflicting_source_id,
                reason=reason,
            ))
            self.state = ResourceInventoryState.CONFLICTED


class ResourceInventory:
    """
    Manages the full inventory of resources found for a case.

    Entries are keyed by (system_id, resource_id).  Observations are
    ingested from EvidenceFact objects; conflicts are detected automatically.
    """

    def __init__(self) -> None:
        self._entries: Dict[Tuple[str, str], InventoryEntry] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest_fact(self, fact: EvidenceFact, audit_at: datetime) -> None:
        """
        Apply one EvidenceFact to the inventory.

        Facts captured after audit_at are silently ignored.
        """
        if fact.captured_at > audit_at:
            return  # strict temporal boundary

        key = (fact.system_id, fact.resource_id)
        entry = self._entries.get(key)
        if entry is None:
            entry = InventoryEntry(
                system_id=fact.system_id,
                resource_id=fact.resource_id,
                data_category=fact.data_category,
                subject_user_id=fact.subject_user_id,
            )
            self._entries[key] = entry

        # Propagate data_category if not yet set
        if entry.data_category is None and fact.data_category is not None:
            entry.data_category = fact.data_category

        new_inv_state = _map_record_state_to_inv(fact.observed_state)
        if new_inv_state is None:
            return  # unrecognized state, skip

        # Conflict check: only upgrade/replace with more recent evidence
        if (
            entry.best_captured_at is not None
            and fact.captured_at == entry.best_captured_at
            and new_inv_state != entry.state
            and entry.state != ResourceInventoryState.UNKNOWN
        ):
            # Same timestamp, different state → CONFLICTED
            entry.mark_conflicted(
                conflicting_source_id=fact.file_id,
                reason=(
                    f"same_capture_time_contradictory_state:"
                    f"{entry.state.value}_vs_{new_inv_state.value}"
                ),
            )
            return

        if (
            entry.best_captured_at is not None
            and fact.captured_at < entry.best_captured_at
            and new_inv_state != entry.state
            and entry.state != ResourceInventoryState.UNKNOWN
        ):
            # Older evidence conflicts with newer — log but don't change state
            logger.debug(
                "Older evidence %s shows different state %s for %s/%s (current: %s)",
                fact.file_id, new_inv_state, fact.system_id, fact.resource_id, entry.state,
            )
            if new_inv_state in (
                ResourceInventoryState.PRESENT,
                ResourceInventoryState.ABSENT_CONFIRMED,
            ):
                # Only flag drift for primary states
                entry.conflicts.append(fact.file_id)
            if fact.file_id not in entry.all_source_ids:
                entry.all_source_ids.append(fact.file_id)
            return

        entry.record_transition(
            new_state=new_inv_state,
            source_id=fact.file_id,
            captured_at=fact.captured_at,
            reason=f"evidence_fact:{fact.observed_state.value}",
        )

    def get(self, system_id: str, resource_id: str) -> Optional[InventoryEntry]:
        return self._entries.get((system_id, resource_id))

    def all_entries(self) -> List[InventoryEntry]:
        return list(self._entries.values())

    def conflicted_entries(self) -> List[InventoryEntry]:
        return [e for e in self._entries.values()
                if e.state == ResourceInventoryState.CONFLICTED]

    def unknown_entries(self) -> List[InventoryEntry]:
        return [e for e in self._entries.values()
                if e.state == ResourceInventoryState.UNKNOWN]


def _map_record_state_to_inv(rs: RecordState) -> Optional[ResourceInventoryState]:
    _MAP = {
        RecordState.ABSENT: ResourceInventoryState.ABSENT_CONFIRMED,
        RecordState.PRESENT: ResourceInventoryState.PRESENT,
        RecordState.REDACTED: ResourceInventoryState.REDACTED_CONFIRMED,
        RecordState.ANONYMIZED: ResourceInventoryState.ANONYMIZED_CONFIRMED,
        RecordState.ACTIVE: ResourceInventoryState.PRESENT,     # active flow
        RecordState.DISABLED: ResourceInventoryState.ABSENT_CONFIRMED,
        RecordState.BLOCKED: ResourceInventoryState.ABSENT_CONFIRMED,
    }
    return _MAP.get(rs)


# ===========================================================================
# B. Temporal Event Processor
# ===========================================================================


class ConflictKind(str, Enum):
    """Categories of temporal conflict in the activity event stream."""
    SAME_TIME_CONTRADICTORY = "SAME_TIME_CONTRADICTORY"   # success+failure same ts
    DUPLICATE_EVENT = "DUPLICATE_EVENT"                    # identical activity_id
    DELAYED_REPLICATION = "DELAYED_REPLICATION"            # replica event after primary delete
    OUT_OF_ORDER = "OUT_OF_ORDER"                          # later event contradicts earlier
    FUTURE_EVENT = "FUTURE_EVENT"                          # event after audit_at
    UNRESOLVABLE = "UNRESOLVABLE"                          # cannot pick winner


@dataclass(frozen=True)
class ConflictRecord:
    """Structured record of a temporal conflict."""
    kind: ConflictKind
    resource_id: str
    source_ids: Tuple[str, ...]   # activity_ids or file_ids involved
    description: str              # no PII
    resolution: str               # how it was resolved


@dataclass
class ActivityEvent:
    """
    Typed wrapper for one row from system_activity.csv.

    Treats reported_result as a *claim*, not proof.
    """
    activity_id: str
    event_time: datetime
    event_type: str        # DELETE_RECORD, SYNC_RECORD, etc.
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str   # SUCCESS / FAILED / PARTIAL — claim only
    details: str           # human-readable, may not be authoritative

    @property
    def is_deletion_claim(self) -> bool:
        return self.event_type in (
            "DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD",
        ) and self.reported_result == "SUCCESS"

    @property
    def is_sync_event(self) -> bool:
        return self.event_type in (
            "SYNC_RECORD", "INDEX_RECORD", "REFRESH_CACHE",
            "CREATE_EXPORT", "RESTORE_BACKUP",
        )

    @property
    def is_flow_control(self) -> bool:
        return self.event_type in (
            "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
            "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS",
        )


# Conflict resolution rules (deterministic, ordered)
# Rule R1: Later timestamp wins over earlier for the same resource.
# Rule R2: For same-timestamp events, SUCCESS+FAILED → CONFLICTED.
# Rule R3: For same-timestamp SUCCESS+SUCCESS → DUPLICATE (keep one, warn).
# Rule R4: Activity after audit_at is a FUTURE_EVENT; ignored for state.
# Rule R5: A SYNC after a DELETE from the same source is DELAYED_REPLICATION.

class TemporalEventProcessor:
    """
    Processes ActivityEvent records for a user's resources to produce
    a claim timeline.  Does NOT override evidence-backed inventory states —
    it only supplies supplementary claims.

    Parameters
    ----------
    events:
        All ActivityEvent rows from system_activity.csv for the relevant
        resource_ids (caller pre-filters by identifier match).
    audit_at:
        Strict cutoff.  Events after audit_at are tagged FUTURE_EVENT.
    """

    def __init__(
        self,
        events: List[ActivityEvent],
        audit_at: datetime,
    ) -> None:
        self._audit_at = _ensure_utc(audit_at)
        self._future: List[ActivityEvent] = []
        self._eligible: List[ActivityEvent] = []
        for ev in events:
            ev_time = _ensure_utc(ev.event_time)
            if ev_time > self._audit_at:
                self._future.append(ev)
            else:
                self._eligible.append(ev)

        # Sort eligible events by (resource_id, event_time)
        self._eligible.sort(key=lambda e: (e.resource_id, _ensure_utc(e.event_time)))
        self._conflicts: List[ConflictRecord] = []
        self._activity_claims: Dict[str, List[ActivityEvent]] = {}
        self._process()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def conflicts(self) -> List[ConflictRecord]:
        return list(self._conflicts)

    @property
    def future_events(self) -> List[ActivityEvent]:
        return list(self._future)

    def claims_for_resource(self, resource_id: str) -> List[ActivityEvent]:
        """Return all eligible activity claims for a resource_id, newest first."""
        return list(reversed(self._activity_claims.get(resource_id, [])))

    def latest_deletion_claim(self, resource_id: str) -> Optional[ActivityEvent]:
        """Return the most recent successful deletion claim, or None."""
        for ev in self.claims_for_resource(resource_id):
            if ev.is_deletion_claim:
                return ev
        return None

    def has_active_sync_after_deletion(self, resource_id: str) -> Optional[ActivityEvent]:
        """
        Return the most recent SYNC event after the latest DELETE claim.
        This pattern suggests the resource may be recreated by a sync job.
        """
        delete_ev = self.latest_deletion_claim(resource_id)
        if delete_ev is None:
            return None
        delete_time = _ensure_utc(delete_ev.event_time)
        for ev in self.claims_for_resource(resource_id):
            if ev.is_sync_event and _ensure_utc(ev.event_time) > delete_time:
                return ev
        return None

    # ------------------------------------------------------------------
    # Internal processing
    # ------------------------------------------------------------------

    def _process(self) -> None:
        """Apply conflict rules to the eligible event stream."""
        seen_ids: Set[str] = set()

        # Group by resource_id
        by_resource: Dict[str, List[ActivityEvent]] = {}
        for ev in self._eligible:
            by_resource.setdefault(ev.resource_id, []).append(ev)

        for resource_id, evs in by_resource.items():
            # R3: deduplicate exact activity_id
            unique_evs = []
            dup_ids = []
            for ev in evs:
                if ev.activity_id in seen_ids:
                    dup_ids.append(ev.activity_id)
                else:
                    seen_ids.add(ev.activity_id)
                    unique_evs.append(ev)
            if dup_ids:
                self._conflicts.append(ConflictRecord(
                    kind=ConflictKind.DUPLICATE_EVENT,
                    resource_id=resource_id,
                    source_ids=tuple(dup_ids),
                    description=f"duplicate_activity_ids_for_resource:{resource_id}",
                    resolution="keep_first_occurrence",
                ))

            # R1 + R2: same-timestamp contradictory results
            # Group by event_time
            by_time: Dict[datetime, List[ActivityEvent]] = {}
            for ev in unique_evs:
                t = _ensure_utc(ev.event_time)
                by_time.setdefault(t, []).append(ev)

            for t, same_time_evs in by_time.items():
                if len(same_time_evs) > 1:
                    results = {e.reported_result for e in same_time_evs}
                    if "SUCCESS" in results and "FAILED" in results:
                        self._conflicts.append(ConflictRecord(
                            kind=ConflictKind.SAME_TIME_CONTRADICTORY,
                            resource_id=resource_id,
                            source_ids=tuple(e.activity_id for e in same_time_evs),
                            description=(
                                f"same_time_success_and_failed_for_resource:{resource_id}"
                            ),
                            resolution="treat_as_unresolvable_claim",
                        ))

            # R5: SYNC after DELETE
            delete_evs = [e for e in unique_evs if e.is_deletion_claim]
            if delete_evs:
                latest_delete_time = max(_ensure_utc(e.event_time) for e in delete_evs)
                sync_after = [
                    e for e in unique_evs
                    if e.is_sync_event
                    and _ensure_utc(e.event_time) > latest_delete_time
                ]
                if sync_after:
                    self._conflicts.append(ConflictRecord(
                        kind=ConflictKind.DELAYED_REPLICATION,
                        resource_id=resource_id,
                        source_ids=tuple(e.activity_id for e in sync_after[:3]),
                        description=(
                            f"sync_event_after_deletion_claim_for_resource:{resource_id}"
                        ),
                        resolution="flag_active_flow_risk",
                    ))

            self._activity_claims[resource_id] = sorted(
                unique_evs, key=lambda e: _ensure_utc(e.event_time)
            )

        # Tag future events as conflicts
        for ev in self._future:
            self._conflicts.append(ConflictRecord(
                kind=ConflictKind.FUTURE_EVENT,
                resource_id=ev.resource_id,
                source_ids=(ev.activity_id,),
                description=f"event_after_audit_at_for_resource:{ev.resource_id}",
                resolution="excluded_from_state_determination",
            ))


# ===========================================================================
# C. Policy Engine (CSV-driven)
# ===========================================================================


@dataclass(frozen=True)
class TypedPolicyRule:
    """
    Strongly-typed representation of one row from deletion_rules.csv.

    All fields come from the actual file; nothing is hardcoded.
    """
    rule_id: str
    data_category: DataCategory
    condition: str          # exact text from CSV
    required_action: RequiredAction
    is_conditional: bool    # True when condition != 'Always'
    retention_mandated: bool  # True when required_action == RETAIN

    @property
    def requires_complete_removal(self) -> bool:
        return self.required_action == RequiredAction.DELETE

    @property
    def requires_identifier_removal(self) -> bool:
        return self.required_action in (RequiredAction.REDACT, RequiredAction.ANONYMIZE)


# Permitted fields after tombstone redaction (rule_15)
_TOMBSTONE_PERMITTED_FIELDS: frozenset = frozenset({"user_id", "subject_reference", "customer_reference"})

# Direct identifiers that must be absent in a compliant tombstone
_TOMBSTONE_FORBIDDEN_IDENTIFIERS: frozenset = frozenset({
    "name", "full_name", "email", "phone", "email_hash",
    "requester_name", "requester_email", "requester_phone",
})


@dataclass
class PolicyViolation:
    """A specific violation of a typed policy rule for one resource."""
    rule_id: str
    rule: TypedPolicyRule
    system_id: str
    resource_id: str
    observed_state: ResourceInventoryState
    required_final_state: ResourceInventoryState
    tombstone_forbidden_fields_present: List[str] = field(default_factory=list)
    evidence_source_id: str = ""
    description: str = ""


class PolicyEngine:
    """
    Parses deletion_rules.csv into TypedPolicyRule objects and evaluates
    each resource against the applicable rule.

    Parsing is done from the actual file; no categories are hardcoded.
    """

    def __init__(self, rules: List[TypedPolicyRule]) -> None:
        self._rules: Dict[DataCategory, TypedPolicyRule] = {
            r.data_category: r for r in rules
        }
        self._all_rules = list(rules)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_csv(cls, csv_path: Path) -> "PolicyEngine":
        """
        Parse deletion_rules.csv and construct a PolicyEngine.

        Expected columns: rule_id, data_category, condition, required_action
        """
        rules = []
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            required_cols = {"rule_id", "data_category", "condition", "required_action"}
            if reader.fieldnames is None or not required_cols.issubset(set(reader.fieldnames)):
                raise ValueError(
                    f"deletion_rules.csv missing required columns. "
                    f"Found: {reader.fieldnames}"
                )
            for row in reader:
                try:
                    cat = DataCategory(row["data_category"].strip())
                except ValueError:
                    logger.warning(
                        "Unknown data_category %r in deletion_rules.csv row %s",
                        row["data_category"], row["rule_id"],
                    )
                    continue
                try:
                    action = RequiredAction(row["required_action"].strip())
                except ValueError:
                    logger.warning(
                        "Unknown required_action %r in deletion_rules.csv row %s",
                        row["required_action"], row["rule_id"],
                    )
                    continue
                condition = row["condition"].strip()
                rules.append(TypedPolicyRule(
                    rule_id=row["rule_id"].strip(),
                    data_category=cat,
                    condition=condition,
                    required_action=action,
                    is_conditional=condition.lower() != "always",
                    retention_mandated=(action == RequiredAction.RETAIN),
                ))
        if not rules:
            raise ValueError("deletion_rules.csv produced zero valid rules")
        return cls(rules)

    @classmethod
    def from_dicts(cls, rows: List[Dict[str, str]]) -> "PolicyEngine":
        """Build a PolicyEngine from pre-parsed row dicts (for testing)."""
        rules = []
        for row in rows:
            try:
                cat = DataCategory(row["data_category"].strip())
                action = RequiredAction(row["required_action"].strip())
            except (KeyError, ValueError):
                continue
            condition = row.get("condition", "Always").strip()
            rules.append(TypedPolicyRule(
                rule_id=row.get("rule_id", ""),
                data_category=cat,
                condition=condition,
                required_action=action,
                is_conditional=condition.lower() != "always",
                retention_mandated=(action == RequiredAction.RETAIN),
            ))
        return cls(rules)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_rule(self, category: DataCategory) -> Optional[TypedPolicyRule]:
        return self._rules.get(category)

    def required_treatment(
        self,
        category: DataCategory,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[RequiredAction]:
        """
        Return the required action for a data category given optional context.

        Context keys evaluated for conditional rules:
          'within_retention_period' (bool)         — rule_12
          'has_legal_hold'           (bool)         — rule_13
          'restore_blockable'        (bool)         — rule_14
          'attachment_belongs_to_subject' (bool)   — rule_06
          'record_attributable'      (bool)         — rule_07/08
          'log_has_email'            (bool)         — rule_11
          'account_deleted'          (bool)         — rule_15
        """
        rule = self._rules.get(category)
        if rule is None:
            return None
        if not rule.is_conditional:
            return rule.required_action

        ctx = context or {}
        # Evaluate condition by data_category (rules from actual CSV)
        if category == DataCategory.SECURITY_AUDIT_LOG:
            # rule_12: retain only within retention period
            return rule.required_action if ctx.get("within_retention_period", True) else None

        if category == DataCategory.LEGAL_HOLD_RECORD:
            return rule.required_action if ctx.get("has_legal_hold", True) else None

        if category == DataCategory.BACKUP_ARCHIVE:
            return rule.required_action if ctx.get("restore_blockable", True) else None

        if category == DataCategory.SUPPORT_ATTACHMENT:
            # rule_06: delete if belongs only to subject; redact otherwise
            if ctx.get("attachment_belongs_to_subject", True):
                return RequiredAction.DELETE
            return RequiredAction.REDACT

        if category in (DataCategory.ANALYTICS_PROFILE, DataCategory.PRODUCT_TELEMETRY):
            # rule_07/08: anonymize only if still attributable
            return rule.required_action if ctx.get("record_attributable", True) else None

        if category == DataCategory.EMAIL_DELIVERY_LOG:
            # rule_11: redact only if log contains the email
            return rule.required_action if ctx.get("log_has_email", True) else None

        if category == DataCategory.ACCOUNT_TOMBSTONE:
            # rule_15: redact direct identifiers if account is deleted
            return rule.required_action if ctx.get("account_deleted", True) else None

        return rule.required_action

    def evaluate_inventory(
        self,
        entry: InventoryEntry,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[PolicyViolation]:
        """
        Evaluate one InventoryEntry against its applicable rule.

        Returns a PolicyViolation if the entry's state does not satisfy
        the required treatment, or None if compliant.
        """
        if entry.data_category is None:
            return None  # can't evaluate without category

        action = self.required_treatment(entry.data_category, context)
        if action is None:
            return None  # no applicable rule after condition evaluation

        rule = self._rules[entry.data_category]
        required_inv_state = _action_to_inv_state(action)

        # --- Tombstone special check ---
        if entry.data_category == DataCategory.ACCOUNT_TOMBSTONE:
            return self._check_tombstone(entry, rule, required_inv_state)

        # --- Email hash is NOT treated as anonymous by default ---
        # An email_hash field present in a record that should be REDACTED is
        # still a violation unless the hash is explicitly removed/nulled.
        # This is enforced by requiring REDACTED_CONFIRMED (not just present with hash).

        # State already compliant
        if entry.state == required_inv_state:
            return None
        # Absent is acceptable for any delete/redact/anonymize requirement
        if (
            action in (RequiredAction.DELETE, RequiredAction.REDACT, RequiredAction.ANONYMIZE)
            and entry.state == ResourceInventoryState.ABSENT_CONFIRMED
        ):
            return None

        # Unknown state → cannot confirm compliance
        if entry.state == ResourceInventoryState.UNKNOWN:
            return PolicyViolation(
                rule_id=rule.rule_id,
                rule=rule,
                system_id=entry.system_id,
                resource_id=entry.resource_id,
                observed_state=entry.state,
                required_final_state=required_inv_state,
                evidence_source_id=entry.best_source_id,
                description=(
                    f"insufficient_evidence:no_coverage_for_{entry.resource_id}"
                ),
            )

        # Conflicted state → cannot confirm compliance
        if entry.state == ResourceInventoryState.CONFLICTED:
            return PolicyViolation(
                rule_id=rule.rule_id,
                rule=rule,
                system_id=entry.system_id,
                resource_id=entry.resource_id,
                observed_state=entry.state,
                required_final_state=required_inv_state,
                evidence_source_id=entry.best_source_id,
                description=(
                    f"conflicted_evidence:cannot_confirm_{action.value}_for_{entry.resource_id}"
                ),
            )

        # Mismatch
        return PolicyViolation(
            rule_id=rule.rule_id,
            rule=rule,
            system_id=entry.system_id,
            resource_id=entry.resource_id,
            observed_state=entry.state,
            required_final_state=required_inv_state,
            evidence_source_id=entry.best_source_id,
            description=(
                f"state_mismatch:{entry.state.value}_requires_{required_inv_state.value}"
            ),
        )

    def _check_tombstone(
        self,
        entry: InventoryEntry,
        rule: TypedPolicyRule,
        required_inv_state: ResourceInventoryState,
    ) -> Optional[PolicyViolation]:
        """
        Tombstone check (rule_15): user_id may survive, but direct identifiers
        (name, email, phone, email_hash) must be absent.

        A tombstone with state REDACTED_CONFIRMED passes.
        A tombstone PRESENT is a violation (PII may still be there).
        """
        if entry.state == ResourceInventoryState.REDACTED_CONFIRMED:
            return None  # compliant
        if entry.state == ResourceInventoryState.ABSENT_CONFIRMED:
            return None  # acceptable — record was fully deleted
        if entry.state in (ResourceInventoryState.UNKNOWN, ResourceInventoryState.CONFLICTED):
            return PolicyViolation(
                rule_id=rule.rule_id,
                rule=rule,
                system_id=entry.system_id,
                resource_id=entry.resource_id,
                observed_state=entry.state,
                required_final_state=required_inv_state,
                evidence_source_id=entry.best_source_id,
                description=f"tombstone_state_uncertain:{entry.state.value}",
            )
        # PRESENT: direct identifiers may still be in the record
        return PolicyViolation(
            rule_id=rule.rule_id,
            rule=rule,
            system_id=entry.system_id,
            resource_id=entry.resource_id,
            observed_state=entry.state,
            required_final_state=required_inv_state,
            evidence_source_id=entry.best_source_id,
            description=(
                "tombstone_direct_identifiers_may_remain:"
                "name/email/phone/email_hash_must_be_removed"
            ),
        )


def _action_to_inv_state(action: RequiredAction) -> ResourceInventoryState:
    return {
        RequiredAction.DELETE: ResourceInventoryState.ABSENT_CONFIRMED,
        RequiredAction.REDACT: ResourceInventoryState.REDACTED_CONFIRMED,
        RequiredAction.ANONYMIZE: ResourceInventoryState.ANONYMIZED_CONFIRMED,
        RequiredAction.RETAIN: ResourceInventoryState.PRESENT,
    }[action]


# ===========================================================================
# D. Data Flow and Restore Risk Analyzer
# ===========================================================================


class FlowStatus(str, Enum):
    ACTIVE = "ACTIVE"       # flow is enabled and operating at audit_at
    HISTORICAL = "HISTORICAL"  # flow existed but was disabled before audit_at
    UNKNOWN = "UNKNOWN"     # no clear evidence of current status


@dataclass
class DataFlowRecord:
    """
    Evidence-backed directed data flow between a source and destination.

    A flow is ACTIVE when it can copy or recreate user data.
    A flow that was disabled before audit_at is HISTORICAL.
    """
    resource_id: str           # data_flow_<N>
    source_system: str
    destination_system: str
    subject_selector: Optional[str]   # email or user_id scoping the flow
    status: FlowStatus
    evidence_source_id: str
    captured_at: datetime
    connector_name: Optional[str] = None

    @property
    def is_active_risk(self) -> bool:
        return self.status == FlowStatus.ACTIVE


@dataclass
class RestoreRiskRecord:
    """
    Evidence-backed backup/restore path that could recreate deleted data.

    restore_blocked=True means the path is already blocked (no risk).
    """
    resource_id: str       # backup_<N>
    archive_key: Optional[str]
    restore_blocked: bool
    evidence_source_id: str
    captured_at: datetime

    @property
    def is_active_risk(self) -> bool:
        return not self.restore_blocked


class DataFlowAnalyzer:
    """
    Analyzes EvidenceFacts to separate active from historical data flows
    and to identify restore risks, using directed source/destination modeling.
    """

    def __init__(self, facts: List[EvidenceFact], audit_at: datetime) -> None:
        self._audit_at = _ensure_utc(audit_at)
        self._eligible = [
            f for f in facts
            if _ensure_utc(f.captured_at) <= self._audit_at
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def active_flows(self) -> List[DataFlowRecord]:
        """Return flows that are currently ACTIVE at audit_at."""
        return [f for f in self._all_flows() if f.is_active_risk]

    def historical_flows(self) -> List[DataFlowRecord]:
        """Return flows that were disabled before audit_at."""
        return [f for f in self._all_flows() if f.status == FlowStatus.HISTORICAL]

    def restore_risks(self) -> List[RestoreRiskRecord]:
        """Return all backup/restore paths, active risks first."""
        return sorted(
            self._all_restore_risks(),
            key=lambda r: (not r.is_active_risk, r.resource_id),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _all_flows(self) -> List[DataFlowRecord]:
        """Deduplicate by resource_id keeping most recent eligible fact."""
        latest: Dict[str, EvidenceFact] = {}
        for fact in self._eligible:
            rid = fact.resource_id
            if not rid.startswith("data_flow"):
                continue
            existing = latest.get(rid)
            if existing is None or fact.captured_at > existing.captured_at:
                latest[rid] = fact

        records = []
        for rid, fact in latest.items():
            # Determine status
            if fact.observed_state in (RecordState.DISABLED, RecordState.ABSENT):
                status = FlowStatus.HISTORICAL
            elif fact.observed_state in (RecordState.PRESENT, RecordState.ACTIVE):
                status = FlowStatus.ACTIVE
            else:
                status = FlowStatus.UNKNOWN

            # Parse connector metadata from raw_value JSON
            connector_name = None
            subject_selector = fact.subject_email
            if fact.raw_value:
                import json as _json
                try:
                    rec = _json.loads(fact.raw_value)
                    connector_name = rec.get("connector_name")
                    if not subject_selector:
                        subject_selector = rec.get("subject_selector") or rec.get("customer_email")
                except Exception:
                    pass

            records.append(DataFlowRecord(
                resource_id=rid,
                source_system=fact.system_id or "integration_service",
                destination_system=fact.system_id or "integration_service",
                subject_selector=subject_selector,
                status=status,
                evidence_source_id=fact.file_id,
                captured_at=_ensure_utc(fact.captured_at),
                connector_name=connector_name,
            ))
        return records

    def _all_restore_risks(self) -> List[RestoreRiskRecord]:
        latest: Dict[str, EvidenceFact] = {}
        for fact in self._eligible:
            rid = fact.resource_id
            if not rid.startswith("backup"):
                continue
            existing = latest.get(rid)
            if existing is None or fact.captured_at > existing.captured_at:
                latest[rid] = fact

        records = []
        for rid, fact in latest.items():
            restore_blocked = fact.observed_state in (
                RecordState.BLOCKED, RecordState.DISABLED, RecordState.ABSENT,
            )
            archive_key = None
            if fact.raw_value:
                import json as _json
                try:
                    rec = _json.loads(fact.raw_value)
                    archive_key = rec.get("archive_key") or rec.get("archive_path")
                except Exception:
                    pass

            records.append(RestoreRiskRecord(
                resource_id=rid,
                archive_key=archive_key,
                restore_blocked=restore_blocked,
                evidence_source_id=fact.file_id,
                captured_at=_ensure_utc(fact.captured_at),
            ))
        return records


# ===========================================================================
# E. AuditAnalysis — structured result
# ===========================================================================


@dataclass
class EvidenceGap:
    """A resource for which evidence coverage is insufficient."""
    system_id: str
    resource_id: str
    reason: str           # e.g. 'no_eligible_evidence', 'conflicted_state'
    source_ids_checked: List[str] = field(default_factory=list)


@dataclass
class RetainedRecord:
    """A record that policy requires to be retained and verified as present."""
    system_id: str
    resource_id: str
    rule_id: str
    data_category: DataCategory
    evidence_source_id: str


@dataclass
class AuditAnalysis:
    """
    Complete structured audit result for one case.

    This is the canonical intermediate representation produced by AuditCore.
    Step generation and status decisions consume this; they must not
    separately re-read raw evidence.
    """
    case_id: str
    user_id: Optional[str]
    audit_at: datetime

    # Policy violations (resources not in required state)
    violations: List[PolicyViolation] = field(default_factory=list)

    # Active flows that can recreate data
    active_flows: List[DataFlowRecord] = field(default_factory=list)

    # Restore risks from backup/restore paths
    restore_risks: List[RestoreRiskRecord] = field(default_factory=list)

    # Records that policy requires to be retained (VERIFY_RECORD_PRESENT)
    retained_records: List[RetainedRecord] = field(default_factory=list)

    # Resources that are confirmed compliant (for COMPLETE verification steps)
    compliant_resources: List[InventoryEntry] = field(default_factory=list)

    # Evidence gaps
    evidence_gaps: List[EvidenceGap] = field(default_factory=list)

    # Temporal conflicts detected
    temporal_conflicts: List[ConflictRecord] = field(default_factory=list)

    # All activity events after audit_at (diagnostic only)
    future_events: List[ActivityEvent] = field(default_factory=list)

    # All inventory entries (for downstream consumers)
    inventory: List[InventoryEntry] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """Deletion is complete iff there are no violations, active flows,
        or un-blocked restore risks."""
        return (
            not self.violations
            and not self.active_flows
            and not any(r.is_active_risk for r in self.restore_risks)
        )

    @property
    def has_evidence_gaps(self) -> bool:
        return bool(self.evidence_gaps)

    def summary(self) -> str:
        """One-line diagnostic (no PII)."""
        return (
            f"case={self.case_id} user={self.user_id} "
            f"violations={len(self.violations)} "
            f"active_flows={len(self.active_flows)} "
            f"restore_risks={sum(1 for r in self.restore_risks if r.is_active_risk)} "
            f"retained={len(self.retained_records)} "
            f"gaps={len(self.evidence_gaps)}"
        )


# ===========================================================================
# F. AuditCore — orchestrates all components
# ===========================================================================


class AuditCore:
    """
    Orchestrates temporal reconstruction, policy evaluation, flow analysis,
    and evidence sufficiency checking for a single case.

    This module is deterministic: no LLM calls, no randomness.

    Parameters
    ----------
    policy_engine:
        Pre-built PolicyEngine from deletion_rules.csv.
    """

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self._policy = policy_engine

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze_case(
        self,
        case_id: str,
        user_id: Optional[str],
        audit_at: datetime,
        evidence_facts: List[EvidenceFact],
        activity_events: Optional[List[ActivityEvent]] = None,
        context_map: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> AuditAnalysis:
        """
        Produce a complete AuditAnalysis for one case.

        Parameters
        ----------
        case_id:
            Identifier for logging (no PII in logs).
        user_id:
            Resolved stable user reference, or None.
        audit_at:
            Strict cutoff; UTC-aware datetime.
        evidence_facts:
            All EvidenceFacts linked to this user's identifiers,
            already filtered to the user (may include post-cutoff facts which
            will be silently ignored).
        activity_events:
            System-activity events for this user's resources (optional).
            Treated as claims, not authoritative state.
        context_map:
            Optional per-resource_id context dicts for conditional rules.
        """
        audit_at = _ensure_utc(audit_at)
        analysis = AuditAnalysis(
            case_id=case_id,
            user_id=user_id,
            audit_at=audit_at,
        )

        # ----------------------------------------------------------------
        # Step 1: Build resource inventory from evidence facts
        # ----------------------------------------------------------------
        inventory = ResourceInventory()
        for fact in evidence_facts:
            inventory.ingest_fact(fact, audit_at)

        entries = inventory.all_entries()
        analysis.inventory = entries

        # ----------------------------------------------------------------
        # Step 2: Process activity events (temporal conflict detection)
        # ----------------------------------------------------------------
        temporal = TemporalEventProcessor(activity_events or [], audit_at)
        analysis.temporal_conflicts = temporal.conflicts
        analysis.future_events = temporal.future_events

        # ----------------------------------------------------------------
        # Step 3: Data flow and restore risk analysis
        # ----------------------------------------------------------------
        flow_analyzer = DataFlowAnalyzer(evidence_facts, audit_at)
        analysis.active_flows = flow_analyzer.active_flows()
        analysis.restore_risks = flow_analyzer.restore_risks()

        # ----------------------------------------------------------------
        # Step 4: Policy evaluation for each inventory entry
        # ----------------------------------------------------------------
        ctx_map = context_map or {}
        for entry in entries:
            # Skip data flow and backup resources — handled by flow analysis
            if entry.resource_id.startswith("data_flow"):
                continue
            if entry.resource_id.startswith("backup"):
                # Backup restore risk is handled by DataFlowAnalyzer
                continue

            ctx = ctx_map.get(entry.resource_id, {})
            # Preserve the evaluated policy treatment in AuditAnalysis so
            # downstream status/step planning never performs a second policy
            # lookup or lets a model author an action.
            entry.required_action = self._policy.required_treatment(
                entry.data_category, ctx
            ) if entry.data_category is not None else None
            violation = self._policy.evaluate_inventory(entry, ctx)
            if violation is not None:
                analysis.violations.append(violation)
            else:
                # Compliant — record for COMPLETE verification steps
                if entry.state not in (
                    ResourceInventoryState.UNKNOWN,
                    ResourceInventoryState.CONFLICTED,
                ):
                    analysis.compliant_resources.append(entry)

            # Collect retained records (RETAIN policy = must stay present)
            if (
                entry.data_category is not None
                and self._policy.required_treatment(entry.data_category, ctx)
                == RequiredAction.RETAIN
                and entry.state == ResourceInventoryState.PRESENT
            ):
                rule = self._policy.get_rule(entry.data_category)
                analysis.retained_records.append(RetainedRecord(
                    system_id=entry.system_id,
                    resource_id=entry.resource_id,
                    rule_id=rule.rule_id if rule else "",
                    data_category=entry.data_category,
                    evidence_source_id=entry.best_source_id,
                ))

        # ----------------------------------------------------------------
        # Step 5: Evidence gap detection
        # ----------------------------------------------------------------
        for entry in inventory.unknown_entries():
            analysis.evidence_gaps.append(EvidenceGap(
                system_id=entry.system_id,
                resource_id=entry.resource_id,
                reason="no_eligible_evidence",
                source_ids_checked=list(entry.all_source_ids),
            ))
        for entry in inventory.conflicted_entries():
            analysis.evidence_gaps.append(EvidenceGap(
                system_id=entry.system_id,
                resource_id=entry.resource_id,
                reason="conflicted_state",
                source_ids_checked=list(entry.all_source_ids + entry.conflicts),
            ))

        # ----------------------------------------------------------------
        # Step 6: Sync-recreates-delete pattern from activity events
        # ----------------------------------------------------------------
        # For each resource that has a successful deletion claim but also
        # a subsequent sync event, surface as an active flow warning.
        for entry in entries:
            if entry.state == ResourceInventoryState.ABSENT_CONFIRMED:
                sync_ev = temporal.has_active_sync_after_deletion(entry.resource_id)
                if sync_ev is not None:
                    # A sync after the deletion claim can recreate the record
                    analysis.active_flows.append(DataFlowRecord(
                        resource_id=f"sync_{entry.resource_id}",
                        source_system=sync_ev.source_system,
                        destination_system=sync_ev.target_system,
                        subject_selector=None,
                        status=FlowStatus.ACTIVE,
                        evidence_source_id=sync_ev.activity_id,
                        captured_at=_ensure_utc(sync_ev.event_time),
                    ))

        logger.debug("AuditCore.analyze_case: %s", analysis.summary())
        return analysis
