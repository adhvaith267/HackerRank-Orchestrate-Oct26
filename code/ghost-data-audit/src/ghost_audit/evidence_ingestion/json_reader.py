"""
json_reader.py — JSON evidence reader for ghost-data-audit evidence ingestion.

Handles five JSON file variants used in the evidence corpus plus a fallback
generic-records path, extracting EvidenceFacts for any record that contains
a subject identifier.

Public API:
    JSONReader(gap_tracker, cache=None)
    .read(ref: EvidenceRef, file_path: Path, identifiers: Set[str]) -> List[EvidenceFact]

Variant detection order
-----------------------
1. 'snapshots' key present            → snapshot_bundle
2. 'service_exports' key present      → service_resource_export
3. Top-level is a list                → flat_list
4. 'records' key + items have 'system'/'result'  → ledger
5. 'records' key + items have 'owner_email'      → customer_export_jobs
6. Anything else with 'records'       → generic_records

State inference rules
---------------------
result='NOT_FOUND' / status_code=404 / profile=None     → ABSENT
result='ANONYMIZED'                                      → ANONYMIZED
result='REDACTED'                                        → REDACTED
result='ACTIVE'/'FOUND'/'IDENTIFIABLE'                  → PRESENT
result='BLOCKED'                                         → BLOCKED
enabled=False                                            → DISABLED
enabled=True                                             → PRESENT
restore_allowed=False                                    → BLOCKED
download_available=False                                 → ABSENT
all PII fields null in analytics record                  → ANONYMIZED
'[REDACTED]' in message_text                             → REDACTED
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from ghost_audit.schemas import (
    DataCategory,
    EvidenceFact,
    EvidenceRef,
    RecordState,
    _parse_utc,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource-id prefix → DataCategory  (mirrors sql_reader / evidence.py)
# ---------------------------------------------------------------------------

_RID_CATEGORY: Dict[str, DataCategory] = {
    "account": DataCategory.USER_PROFILE,
    "search": DataCategory.SEARCH_INDEX_ENTRY,
    "analytics": DataCategory.ANALYTICS_PROFILE,
    "support": DataCategory.SUPPORT_MESSAGE,
    "export": DataCategory.USER_EXPORT,
    "backup": DataCategory.BACKUP_ARCHIVE,
    "audit_record": DataCategory.SECURITY_AUDIT_LOG,
    "tombstone": DataCategory.ACCOUNT_TOMBSTONE,
    "marketing": DataCategory.MARKETING_PROFILE,
    "legal_hold": DataCategory.LEGAL_HOLD_RECORD,
    "email_delivery": DataCategory.EMAIL_DELIVERY_LOG,
    "connector": DataCategory.USER_PROFILE,
    "data_flow": DataCategory.USER_PROFILE,
}

_SYS_CATEGORY: Dict[str, DataCategory] = {
    "account_service": DataCategory.USER_PROFILE,
    "search_service": DataCategory.SEARCH_INDEX_ENTRY,
    "analytics_platform": DataCategory.ANALYTICS_PROFILE,
    "support_platform": DataCategory.SUPPORT_MESSAGE,
    "export_service": DataCategory.USER_EXPORT,
    "backup_service": DataCategory.BACKUP_ARCHIVE,
    "security_service": DataCategory.SECURITY_AUDIT_LOG,
    "identity_service": DataCategory.ACCOUNT_TOMBSTONE,
    "marketing_platform": DataCategory.MARKETING_PROFILE,
    "legal_service": DataCategory.LEGAL_HOLD_RECORD,
    "integration_service": DataCategory.USER_PROFILE,
}


def _resource_category(resource_id: str, system_id: str) -> DataCategory:
    for prefix, cat in _RID_CATEGORY.items():
        if resource_id.startswith(prefix):
            return cat
    return _SYS_CATEGORY.get(system_id, DataCategory.USER_PROFILE)


# ---------------------------------------------------------------------------
# State inference
# ---------------------------------------------------------------------------


def _infer_state(rec: Dict[str, Any]) -> RecordState:
    """
    Apply the full state-inference rule table to a single record dict.

    Rules are evaluated in priority order; the first matching rule wins.
    """
    # result field
    result = str(rec.get("result") or "").upper()
    if result in {"NOT_FOUND", "ABSENT", "DELETED"}:
        return RecordState.ABSENT
    if result == "ANONYMIZED":
        return RecordState.ANONYMIZED
    if result == "REDACTED":
        return RecordState.REDACTED
    if result in {"ACTIVE", "FOUND", "IDENTIFIABLE", "PRESENT"}:
        return RecordState.PRESENT
    if result == "BLOCKED":
        return RecordState.BLOCKED
    if result == "DISABLED":
        return RecordState.DISABLED

    # status_code or profile sentinel
    status_code = rec.get("status_code")
    if status_code == 404:
        return RecordState.ABSENT
    profile = rec.get("profile")
    if profile is None and "profile" in rec:
        # key exists but is explicitly null → absent
        return RecordState.ABSENT

    # enabled field (connectors / data flows)
    enabled = rec.get("enabled")
    if enabled is False:
        return RecordState.DISABLED
    if enabled is True:
        return RecordState.PRESENT

    # restore_allowed (backup entries)
    restore_allowed = rec.get("restore_allowed")
    if restore_allowed is False:
        return RecordState.BLOCKED

    # download_available (customer export jobs)
    download_available = rec.get("download_available")
    if download_available is False:
        return RecordState.ABSENT

    # Analytics record with all PII null → anonymized
    if all(
        rec.get(k) is None
        for k in ("user_id", "email", "phone", "email_hash")
    ) and any(k in rec for k in ("user_id", "email", "phone", "email_hash")):
        return RecordState.ANONYMIZED

    # Support: redacted message marker
    mt = str(rec.get("message_text") or "")
    if "[REDACTED]" in mt:
        return RecordState.REDACTED

    # account_status field
    status = str(rec.get("account_status") or "").upper()
    if "DELET" in status or status in {"ABSENT"}:
        return RecordState.ABSENT

    # Default: record is identifiable / present
    return RecordState.PRESENT


# ---------------------------------------------------------------------------
# Identifier matching helpers
# ---------------------------------------------------------------------------


def _matches_any(rec: Any, ids_lower: Set[str]) -> bool:
    """
    Recursively check whether *rec* (dict, list, or scalar) contains any
    value that is a known identifier (case-insensitive).
    """
    if isinstance(rec, str):
        return rec.lower() in ids_lower
    if isinstance(rec, dict):
        return any(_matches_any(v, ids_lower) for v in rec.values())
    if isinstance(rec, list):
        return any(_matches_any(v, ids_lower) for v in rec)
    return False


def _find_matched_email(rec: Dict[str, Any], ids_lower: Set[str]) -> Optional[str]:
    """Return the first email-valued field that matches an identifier."""
    email_keys = (
        "email", "owner_email", "requester_email", "customer_email",
        "subject_email", "email_address",
    )
    for k in email_keys:
        v = rec.get(k)
        if v and isinstance(v, str) and v.lower() in ids_lower:
            return v.lower()
    # Generic fallback: any string value in identifiers
    for v in rec.values():
        if v and isinstance(v, str) and v.lower() in ids_lower:
            return v.lower()
    return None


def _subject_user_id(rec: Dict[str, Any]) -> Optional[str]:
    """Extract a stable user reference from a record."""
    for col in ("user_id", "customer_reference", "subject_reference"):
        v = rec.get(col)
        if v:
            return str(v)
    return None


# ---------------------------------------------------------------------------
# JSONReader
# ---------------------------------------------------------------------------


class JSONReader:
    """
    JSON evidence reader.

    Parameters
    ----------
    gap_tracker:
        Dependency with .warn() / .fatal() for structured gap logging.
    cache:
        Optional shared cache mapping; reserved for future use.
    """

    def __init__(self, gap_tracker: Any, cache: Optional[Any] = None) -> None:
        self._gap = gap_tracker
        self._cache = cache

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def read(
        self,
        ref: EvidenceRef,
        file_path: Path,
        identifiers: Set[str],
    ) -> List[EvidenceFact]:
        """
        Parse *file_path* as JSON and return EvidenceFacts for every record
        that contains any of the supplied *identifiers*.

        Parameters
        ----------
        ref:
            EvidenceRef manifest entry providing file_id and captured_at.
        file_path:
            Path to the .json file.
        identifiers:
            Set of subject identifiers for case-insensitive matching.

        Returns
        -------
        List[EvidenceFact]
            Empty list on parse errors or when no records match.
        """
        if not file_path.exists():
            self._gap.warn(
                file_id=ref.file_id,
                reason="json_file_missing",
                detail=f"JSON file not found: {file_path.name}",
            )
            return []

        try:
            raw = file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except Exception as exc:
            self._gap.warn(
                file_id=ref.file_id,
                reason="json_parse_error",
                detail=f"JSON parse error in {file_path.name}: {exc}",
            )
            return []

        ids_lower: Set[str] = {i.lower() for i in identifiers if i}

        # Variant dispatch
        if isinstance(data, dict) and "snapshots" in data:
            return self._read_snapshot_bundle(ref, data, ids_lower)

        if isinstance(data, dict) and "service_exports" in data:
            return self._read_service_resource_export(ref, data, ids_lower)

        if isinstance(data, list):
            return self._read_flat_list(ref, data, ids_lower)

        if isinstance(data, dict) and "records" in data:
            records = data.get("records") or []
            if not isinstance(records, list) or not records:
                # Empty records list — nothing to do
                return []

            # Peek at first record to decide sub-variant
            first = next((r for r in records if isinstance(r, dict)), None)
            if first is not None:
                if "system" in first or "result" in first:
                    return self._read_ledger(ref, data, ids_lower)
                if "owner_email" in first:
                    return self._read_customer_export_jobs(ref, data, ids_lower)

            # Generic fallback
            return self._read_generic_records(ref, data, ids_lower)

        # Completely unrecognised structure
        self._gap.warn(
            file_id=ref.file_id,
            reason="unknown_json_variant",
            detail=f"Unrecognised JSON structure in {file_path.name}",
        )
        return []

    # ------------------------------------------------------------------
    # Variant: snapshot_bundle
    # {exported_at, source, snapshots:[{captured_at, data_store, collection, records:[...]}]}
    # ------------------------------------------------------------------

    def _read_snapshot_bundle(
        self,
        ref: EvidenceRef,
        data: Dict[str, Any],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        snapshots = data.get("snapshots") or []
        for snap_idx, snap in enumerate(snapshots):
            if not isinstance(snap, dict):
                continue
            sys_id = str(snap.get("data_store") or "")
            collection = str(snap.get("collection") or "")
            records = snap.get("records") or []
            if not isinstance(records, list):
                continue
            for rec_idx, rec in enumerate(records):
                if not isinstance(rec, dict):
                    continue
                if not _matches_any(rec, ids_lower):
                    continue
                try:
                    resource_id = str(rec.get("resource_id") or "")
                    matched_email = _find_matched_email(rec, ids_lower)
                    state = _infer_state(rec)
                    cat = _resource_category(resource_id, sys_id)
                    facts.append(
                        EvidenceFact(
                            file_id=ref.file_id,
                            file_path=ref.file_path,
                            captured_at=ref.captured_at,
                            system_id=sys_id,
                            resource_id=resource_id,
                            subject_user_id=_subject_user_id(rec),
                            subject_email=matched_email,
                            data_category=cat,
                            observed_state=state,
                            raw_value=json.dumps(rec)[:2000],
                            source_span=f"snapshots[{snap_idx}].records[{rec_idx}]",
                            llm_derived=False,
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "snapshot_bundle record parse error [%s] snap=%d rec=%d: %s",
                        ref.file_id,
                        snap_idx,
                        rec_idx,
                        exc,
                    )
        return facts

    # ------------------------------------------------------------------
    # Variant: service_resource_export
    # {exported_at, region, source, service_exports:{svc:{collection:[records]}}}
    # ------------------------------------------------------------------

    def _read_service_resource_export(
        self,
        ref: EvidenceRef,
        data: Dict[str, Any],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        exports = data.get("service_exports") or {}
        if not isinstance(exports, dict):
            return facts
        for svc_name, collections in exports.items():
            if not isinstance(collections, dict):
                continue
            for coll_name, records in collections.items():
                if not isinstance(records, list):
                    continue
                for rec_idx, rec in enumerate(records):
                    if not isinstance(rec, dict):
                        continue
                    if not _matches_any(rec, ids_lower):
                        continue
                    try:
                        resource_id = str(rec.get("resource_id") or "")
                        matched_email = _find_matched_email(rec, ids_lower)
                        state = _infer_state(rec)
                        cat = _resource_category(resource_id, svc_name)
                        facts.append(
                            EvidenceFact(
                                file_id=ref.file_id,
                                file_path=ref.file_path,
                                captured_at=ref.captured_at,
                                system_id=svc_name,
                                resource_id=resource_id,
                                subject_user_id=_subject_user_id(rec),
                                subject_email=matched_email,
                                data_category=cat,
                                observed_state=state,
                                raw_value=json.dumps(rec)[:2000],
                                source_span=(
                                    f"service_exports.{svc_name}"
                                    f".{coll_name}[{rec_idx}]"
                                ),
                                llm_derived=False,
                            )
                        )
                    except Exception as exc:
                        logger.warning(
                            "service_resource_export parse error [%s] "
                            "svc=%s coll=%s rec=%d: %s",
                            ref.file_id,
                            svc_name,
                            coll_name,
                            rec_idx,
                            exc,
                        )
        return facts

    # ------------------------------------------------------------------
    # Variant: flat_list
    # [{...}, ...]  at the top level
    # ------------------------------------------------------------------

    def _read_flat_list(
        self,
        ref: EvidenceRef,
        records: List[Any],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        for rec_idx, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            if not _matches_any(rec, ids_lower):
                continue
            try:
                resource_id = str(rec.get("resource_id") or "")
                sys_id = str(
                    rec.get("system")
                    or rec.get("origin_system")
                    or rec.get("service")
                    or ""
                )
                matched_email = _find_matched_email(rec, ids_lower)
                state = _infer_state(rec)
                cat = _resource_category(resource_id, sys_id)
                facts.append(
                    EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=ref.captured_at,
                        system_id=sys_id,
                        resource_id=resource_id,
                        subject_user_id=_subject_user_id(rec),
                        subject_email=matched_email,
                        data_category=cat,
                        observed_state=state,
                        raw_value=json.dumps(rec)[:2000],
                        source_span=f"[{rec_idx}]",
                        llm_derived=False,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "flat_list record parse error [%s] idx=%d: %s",
                    ref.file_id,
                    rec_idx,
                    exc,
                )
        return facts

    # ------------------------------------------------------------------
    # Variant: ledger / security_audit
    # {exported_at, origin, record_count,
    #  records:[{recorded_at, system, resource_id, record_type, result,
    #            subject_reference}]}
    # Also handles connector_configurations with the same outer shape.
    # ------------------------------------------------------------------

    def _read_ledger(
        self,
        ref: EvidenceRef,
        data: Dict[str, Any],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        records = data.get("records") or []
        for rec_idx, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            if not _matches_any(rec, ids_lower):
                continue
            try:
                resource_id = str(rec.get("resource_id") or "")
                sys_id = str(
                    rec.get("system")
                    or rec.get("origin_system")
                    or data.get("origin")
                    or ""
                )
                matched_email = _find_matched_email(rec, ids_lower)
                state = _infer_state(rec)
                cat = _resource_category(resource_id, sys_id)
                facts.append(
                    EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=ref.captured_at,
                        system_id=sys_id,
                        resource_id=resource_id,
                        subject_user_id=_subject_user_id(rec),
                        subject_email=matched_email,
                        data_category=cat,
                        observed_state=state,
                        raw_value=json.dumps(rec)[:2000],
                        source_span=f"records[{rec_idx}]",
                        llm_derived=False,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "ledger record parse error [%s] idx=%d: %s",
                    ref.file_id,
                    rec_idx,
                    exc,
                )
        return facts

    # ------------------------------------------------------------------
    # Variant: customer_export_jobs
    # {captured_at, source, collection,
    #  records:[{resource_id, owner_email, file_name, created_at,
    #            expires_at, download_available, included_sections}]}
    # ------------------------------------------------------------------

    def _read_customer_export_jobs(
        self,
        ref: EvidenceRef,
        data: Dict[str, Any],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        records = data.get("records") or []
        source = str(data.get("source") or "export_service")
        for rec_idx, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            owner_email = str(rec.get("owner_email") or "")
            if not owner_email or owner_email.lower() not in ids_lower:
                # Fall back to general identifier match
                if not _matches_any(rec, ids_lower):
                    continue
            try:
                resource_id = str(rec.get("resource_id") or "")
                matched_email = _find_matched_email(rec, ids_lower) or owner_email.lower() or None
                state = _infer_state(rec)
                facts.append(
                    EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=ref.captured_at,
                        system_id=source,
                        resource_id=resource_id,
                        subject_user_id=_subject_user_id(rec),
                        subject_email=matched_email,
                        data_category=DataCategory.USER_EXPORT,
                        observed_state=state,
                        raw_value=json.dumps(rec)[:2000],
                        source_span=f"records[{rec_idx}]",
                        llm_derived=False,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "customer_export_jobs parse error [%s] idx=%d: %s",
                    ref.file_id,
                    rec_idx,
                    exc,
                )
        return facts

    # ------------------------------------------------------------------
    # Variant: generic_records
    # {records:[...]} where the inner record structure is not one of the
    # known sub-types.
    # ------------------------------------------------------------------

    def _read_generic_records(
        self,
        ref: EvidenceRef,
        data: Dict[str, Any],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        records = data.get("records") or []
        source = str(
            data.get("source")
            or data.get("origin")
            or data.get("data_store")
            or ""
        )
        for rec_idx, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            if not _matches_any(rec, ids_lower):
                continue
            try:
                resource_id = str(rec.get("resource_id") or "")
                sys_id = str(
                    rec.get("system")
                    or rec.get("origin_system")
                    or source
                )
                matched_email = _find_matched_email(rec, ids_lower)
                state = _infer_state(rec)
                cat = _resource_category(resource_id, sys_id)
                facts.append(
                    EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=ref.captured_at,
                        system_id=sys_id,
                        resource_id=resource_id,
                        subject_user_id=_subject_user_id(rec),
                        subject_email=matched_email,
                        data_category=cat,
                        observed_state=state,
                        raw_value=json.dumps(rec)[:2000],
                        source_span=f"records[{rec_idx}]",
                        llm_derived=False,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "generic_records parse error [%s] idx=%d: %s",
                    ref.file_id,
                    rec_idx,
                    exc,
                )
        return facts
