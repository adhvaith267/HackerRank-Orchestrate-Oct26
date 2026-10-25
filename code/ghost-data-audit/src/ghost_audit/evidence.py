"""
evidence.py — Evidence loading and extraction.

Input contract:
    EvidenceLoader(manifest, dataset_root, config)
    .load_facts_for_user(resolution, audit_at) -> List[EvidenceFact]

Handles all 5 evidence formats:
  - SQL  (customer_data_inventory, read_replica, regional_replicas,
          reporting_replica, failover_replica, primary_only)
  - JSON (snapshot_bundle, service_resource_export, ledger, manifest, etc.)
  - LOG  (structured key=value, search_index_diagnostic, etc.)
  - PDF  (pdftotext + optional LLM)
  - IMAGE (LLM vision)
  - TXT  (shift handover)

All evidence matching is case-insensitive on email addresses.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .config import RunConfig
from .identity import IdentityResolution
from .schemas import (
    DataCategory,
    EvidenceFact,
    EvidenceFormat,
    EvidenceRef,
    LLMConfidence,
    RecordState,
    _parse_utc,
    RunUsage,
)
from .ollama_evidence import FACT_TYPES, OllamaEvidenceExtractor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource-id prefix → DataCategory mapping  (used during SQL extraction)
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
}


def _resource_category(resource_id: str, system_id: str) -> DataCategory:
    for prefix, cat in _RID_CATEGORY.items():
        if resource_id.startswith(prefix):
            return cat
    return _SYS_CATEGORY.get(system_id, DataCategory.USER_PROFILE)


def _is_data_flow(resource_id: str) -> bool:
    return resource_id.startswith("data_flow")


# ---------------------------------------------------------------------------
# State inference helpers
# ---------------------------------------------------------------------------

def _infer_state_from_result(result: str) -> RecordState:
    """Map result/status strings from evidence to RecordState."""
    r = result.upper()
    if r in {"NOT_FOUND", "ABSENT", "404", "DELETED"}:
        return RecordState.ABSENT
    if r in {"ANONYMIZED"}:
        return RecordState.ANONYMIZED
    if r in {"REDACTED"}:
        return RecordState.REDACTED
    if r in {"ACTIVE", "FOUND", "IDENTIFIABLE", "PRESENT"}:
        return RecordState.PRESENT
    if r in {"BLOCKED"}:
        return RecordState.BLOCKED
    if r in {"DISABLED"}:
        return RecordState.DISABLED
    # Default: assume present if unrecognised
    return RecordState.PRESENT


# ---------------------------------------------------------------------------
# EvidenceLoader
# ---------------------------------------------------------------------------

class EvidenceLoader:
    """
    Loads and parses all evidence files, returning EvidenceFact objects for a
    given user identity resolution.

    Parameters
    ----------
    manifest : List[EvidenceRef]
        Loaded from evidence_files.csv.
    dataset_root : Path
        The dataset/ directory path.
    config : RunConfig
    """

    def __init__(
        self,
        manifest: List[EvidenceRef],
        dataset_root: Path,
        config: RunConfig,
        usage: Optional[RunUsage] = None,
    ) -> None:
        self._manifest = {ref.file_id: ref for ref in manifest}
        self._dataset_root = dataset_root
        self._config = config
        self._ollama = OllamaEvidenceExtractor(
            config.llm,
            usage=usage,
            cache_dir=config.output.cache_dir,
        )

    def load_facts_for_user(
        self,
        resolution: IdentityResolution,
        audit_at: datetime,
    ) -> List[EvidenceFact]:
        """
        Return all EvidenceFacts linked to the user in eligible evidence files.

        Only processes evidence with captured_at <= audit_at.
        """
        if not resolution.found:
            return []

        # Pre-build a normalised set of identifiers for fast matching
        ids = resolution.all_identifiers
        ids_lower = {i.lower() for i in ids if i}
        ids_upper = {i.upper() for i in ids if i}
        all_ids = ids_lower | ids_upper | ids

        facts: List[EvidenceFact] = []
        for ref in self._manifest.values():
            if ref.captured_at > audit_at:
                continue  # Evidence captured after audit cutoff — skip
            try:
                file_facts = self._extract_file(ref, resolution, all_ids)
                file_facts.extend(self._extract_ollama_candidates(ref, file_facts, resolution, audit_at))
                facts.extend(file_facts)
            except Exception as exc:
                logger.warning("Failed to extract evidence from %s: %s", ref.file_id, exc)
        return facts

    def _extract_ollama_candidates(
        self,
        ref: EvidenceRef,
        deterministic_facts: List[EvidenceFact],
        resolution: IdentityResolution,
        audit_at: datetime,
    ) -> List[EvidenceFact]:
        """Optionally enrich existing unstructured facts without inventing IDs.

        Candidate facts are accepted only when their resource already exists in
        deterministic evidence.  The audit core still adjudicates conflicts and
        policy; this adapter merely converts grounded candidates into typed
        evidence facts with ``llm_derived=True``.
        """
        if ref.format not in {EvidenceFormat.LOG, EvidenceFormat.TXT, EvidenceFormat.PDF, EvidenceFormat.IMAGE}:
            return []
        if self._config.llm.mode == "off":
            return []
        if self._config.llm.mode == "auto" and deterministic_facts and not any(
            f.needs_review for f in deterministic_facts
        ):
            return []
        excerpt = "\n".join(f.raw_value for f in deterministic_facts if f.raw_value)
        if not excerpt:
            return []
        known_by_resource = {f.resource_id: f for f in deterministic_facts if f.resource_id}
        deterministic_types = {
            "resource_presence", "flow_state", "restore_state"
        } if known_by_resource else set()
        candidates = self._ollama.extract(
            excerpt,
            manifest_file_id=ref.file_id,
            allowed_source_ids={ref.file_id},
            known_resource_ids=known_by_resource,
            stable_user_id=resolution.user_id,
            audit_at=audit_at,
            evidence_captured_at=ref.captured_at,
            allowed_fact_types=FACT_TYPES,
            deterministic_fact_types=deterministic_types,
        )
        facts: List[EvidenceFact] = []
        for candidate in candidates:
            if not candidate.resource_id or candidate.resource_id not in known_by_resource:
                continue
            base = known_by_resource[candidate.resource_id]
            state = base.observed_state
            if candidate.fact_type in {"resource_presence", "flow_state", "restore_state"}:
                try:
                    state = RecordState(str(candidate.value))
                except ValueError:
                    continue
            facts.append(EvidenceFact(
                file_id=ref.file_id,
                file_path=ref.file_path,
                captured_at=ref.captured_at,
                system_id=base.system_id,
                resource_id=base.resource_id,
                subject_user_id=resolution.user_id,
                subject_email=resolution.input_email,
                data_category=base.data_category,
                observed_state=state,
                raw_value=candidate.quote,
                source_span=candidate.source_span,
                llm_derived=True,
                llm_confidence=LLMConfidence(candidate.confidence),
                needs_review=candidate.confidence == "low",
            ))
        return facts

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def _extract_file(
        self,
        ref: EvidenceRef,
        resolution: IdentityResolution,
        all_ids: Set[str],
    ) -> List[EvidenceFact]:
        full_path = self._dataset_root / ref.file_path
        if not full_path.exists():
            logger.warning("Evidence file not found: %s", full_path)
            return []

        if ref.format == EvidenceFormat.SQL:
            return self._extract_sql(ref, full_path, resolution, all_ids)
        if ref.format == EvidenceFormat.JSON:
            return self._extract_json(ref, full_path, resolution, all_ids)
        if ref.format == EvidenceFormat.LOG:
            return self._extract_log(ref, full_path, resolution, all_ids)
        if ref.format == EvidenceFormat.PDF:
            return self._extract_pdf(ref, full_path, resolution, all_ids)
        if ref.format == EvidenceFormat.IMAGE:
            return self._extract_image(ref, full_path, resolution, all_ids)
        if ref.format == EvidenceFormat.TXT:
            return self._extract_txt(ref, full_path, resolution, all_ids)
        return []

    # ------------------------------------------------------------------
    # SQL extraction
    # ------------------------------------------------------------------

    def _extract_sql(
        self,
        ref: EvidenceRef,
        path: Path,
        resolution: IdentityResolution,
        all_ids: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        sql_text = path.read_text(encoding="utf-8", errors="replace")

        # Load into a temporary in-memory SQLite database
        with sqlite3.connect(":memory:") as conn:
            conn.executescript(sql_text)
            facts.extend(self._query_inventory_tables(ref, conn, resolution, all_ids))
            facts.extend(self._query_blob_tables(ref, conn, resolution, all_ids))
            facts.extend(self._query_failover_flat(ref, conn, resolution, all_ids))

        return facts

    def _query_inventory_tables(
        self, ref: EvidenceRef, conn: sqlite3.Connection,
        resolution: IdentityResolution, all_ids: Set[str],
    ) -> List[EvidenceFact]:
        """Query the customer_data_inventory flat-schema tables."""
        facts: List[EvidenceFact] = []
        tables = {
            "customer_profiles": ("account_service", DataCategory.USER_PROFILE),
            "customer_search_documents": ("search_service", DataCategory.SEARCH_INDEX_ENTRY),
            "customer_analytics_profiles": ("analytics_platform", DataCategory.ANALYTICS_PROFILE),
            "support_records": ("support_platform", DataCategory.SUPPORT_MESSAGE),
            "customer_exports": ("export_service", DataCategory.USER_EXPORT),
            "connector_subscriptions": ("integration_service", DataCategory.USER_PROFILE),
            "backup_restore_entries": ("backup_service", DataCategory.BACKUP_ARCHIVE),
            "security_audit_records": ("security_service", DataCategory.SECURITY_AUDIT_LOG),
        }
        existing = self._get_existing_tables(conn)
        for table, (sys_id, cat) in tables.items():
            if table not in existing:
                continue
            try:
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                col_names = [d[0] for d in conn.execute(
                    f"SELECT * FROM {table} LIMIT 0"
                ).description]
                for row in rows:
                    rdict = dict(zip(col_names, row))
                    if not self._row_matches(rdict, all_ids):
                        continue
                    resource_id = rdict.get("resource_id", "")
                    state = self._infer_inventory_state(table, rdict)
                    facts.append(EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=ref.captured_at,
                        system_id=sys_id,
                        resource_id=resource_id,
                        subject_user_id=resolution.user_id,
                        subject_email=resolution.input_email,
                        data_category=cat,
                        observed_state=state,
                        raw_value=str(rdict)[:self._config.llm.max_evidence_chars],
                        source_span=f"table:{table}",
                    ))
            except Exception as exc:
                logger.debug("SQL query error table=%s: %s", table, exc)
        return facts

    def _query_blob_tables(
        self, ref: EvidenceRef, conn: sqlite3.Connection,
        resolution: IdentityResolution, all_ids: Set[str],
    ) -> List[EvidenceFact]:
        """Query read_replica / regional_replicas / reporting_replica blob tables."""
        facts: List[EvidenceFact] = []
        existing = self._get_existing_tables(conn)
        blob_tables = [t for t in existing if "primary" in t or "replica" in t or "read" in t]
        for table in blob_tables:
            try:
                rows = conn.execute(
                    f"SELECT resource_id, origin_system, collection_name, record_json, updated_at FROM {table}"
                ).fetchall()
                for (resource_id, origin_system, collection_name, record_json, updated_at) in rows:
                    try:
                        rec = json.loads(record_json)
                    except Exception:
                        rec = {}
                    if not self._record_matches(rec, all_ids):
                        continue
                    state = self._infer_blob_state(collection_name, rec)
                    cat = _resource_category(resource_id, origin_system)
                    facts.append(EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=ref.captured_at,
                        system_id=origin_system,
                        resource_id=resource_id,
                        subject_user_id=resolution.user_id,
                        subject_email=resolution.input_email,
                        data_category=cat,
                        observed_state=state,
                        raw_value=record_json[:self._config.llm.max_evidence_chars],
                        source_span=f"table:{table}",
                    ))
            except Exception as exc:
                logger.debug("Blob table query %s: %s", table, exc)
        return facts

    def _query_failover_flat(
        self, ref: EvidenceRef, conn: sqlite3.Connection,
        resolution: IdentityResolution, all_ids: Set[str],
    ) -> List[EvidenceFact]:
        """Query flat-schema failover_replica tables (customer_profiles_*)."""
        facts: List[EvidenceFact] = []
        existing = self._get_existing_tables(conn)
        flat_tables = [t for t in existing if "profiles" in t and "primary" not in t
                       and "blob" not in t]
        for table in flat_tables:
            try:
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                col_names = [d[0] for d in conn.execute(
                    f"SELECT * FROM {table} LIMIT 0"
                ).description]
                for row in rows:
                    rdict = dict(zip(col_names, row))
                    if not self._row_matches(rdict, all_ids):
                        continue
                    resource_id = rdict.get("resource_id", "")
                    state = RecordState.PRESENT
                    facts.append(EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=ref.captured_at,
                        system_id="account_service",
                        resource_id=resource_id,
                        subject_user_id=resolution.user_id,
                        subject_email=resolution.input_email,
                        data_category=DataCategory.USER_PROFILE,
                        observed_state=state,
                        raw_value=str(rdict)[:self._config.llm.max_evidence_chars],
                        source_span=f"table:{table}",
                    ))
            except Exception as exc:
                logger.debug("Failover flat table %s: %s", table, exc)
        return facts

    @staticmethod
    def _get_existing_tables(conn: sqlite3.Connection) -> Set[str]:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        return {r[0] for r in rows}

    def _row_matches(self, rdict: Dict, all_ids: Set[str]) -> bool:
        """Return True if any column value in rdict matches a known identifier."""
        for col, val in rdict.items():
            if val and isinstance(val, str) and val.lower() in {i.lower() for i in all_ids}:
                return True
        return False

    def _record_matches(self, rec: Dict, all_ids: Set[str]) -> bool:
        """Recursively check a JSON record for identifier matches."""
        ids_lower = {i.lower() for i in all_ids if i}
        for val in rec.values():
            if isinstance(val, str) and val.lower() in ids_lower:
                return True
            if isinstance(val, dict):
                if self._record_matches(val, all_ids):
                    return True
        return False

    @staticmethod
    def _infer_inventory_state(table: str, rdict: Dict) -> RecordState:
        """Infer state from inventory table row fields."""
        status = (rdict.get("account_status") or rdict.get("last_delivery_status") or "").upper()
        if "DELETION" in status or status in {"DELETED", "ABSENT"}:
            return RecordState.ABSENT
        enabled = rdict.get("enabled")
        if enabled is not None:
            return RecordState.PRESENT if enabled else RecordState.DISABLED
        restore_allowed = rdict.get("restore_allowed")
        if restore_allowed is not None:
            return RecordState.PRESENT if restore_allowed else RecordState.BLOCKED
        # Customer identifiers present = record is identifiable/present
        for col in ("email", "phone", "email_hash", "requester_email", "owner_email", "customer_email"):
            if rdict.get(col):
                return RecordState.PRESENT
        return RecordState.PRESENT

    @staticmethod
    def _infer_blob_state(collection_name: str, rec: Dict) -> RecordState:
        """Infer state from a blob record's JSON content."""
        # Anonymized: no user_id/email/phone/email_hash
        if collection_name in ("customer_analytics_reports",):
            if all(rec.get(k) is None for k in ("user_id", "email", "phone", "email_hash")):
                return RecordState.ANONYMIZED
            return RecordState.PRESENT
        # Support: check for [REDACTED] marker
        if collection_name in ("support_conversations", "support_tickets"):
            mt = rec.get("message_text", "")
            if "[REDACTED]" in str(mt):
                return RecordState.REDACTED
            return RecordState.PRESENT
        # Backup: check restore_allowed
        if collection_name == "backup_catalog":
            if rec.get("restore_allowed") is False:
                return RecordState.BLOCKED
            return RecordState.PRESENT
        # Connectors: check enabled
        if collection_name == "connector_configurations":
            if rec.get("enabled") is True:
                return RecordState.PRESENT  # active/enabled
            return RecordState.DISABLED
        # Account profiles
        if collection_name in ("customer_profiles",):
            status = (rec.get("account_status") or "").upper()
            if "DELET" in status:
                return RecordState.ABSENT
            return RecordState.PRESENT
        return RecordState.PRESENT

    # ------------------------------------------------------------------
    # JSON extraction
    # ------------------------------------------------------------------

    def _extract_json(
        self,
        ref: EvidenceRef,
        path: Path,
        resolution: IdentityResolution,
        all_ids: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            logger.warning("JSON parse error %s: %s", path, exc)
            return []

        # Snapshot bundle: {snapshots:[{data_store, collection, captured_at, records:[]}]}
        if "snapshots" in data:
            for snap in data.get("snapshots", []):
                cap_at = _parse_utc(snap.get("captured_at", ref.captured_at.isoformat()))
                if cap_at > resolution.__class__.__mro__[0].__dict__.get("__audit_at__", ref.captured_at):
                    pass  # We can't check audit_at here; caller filters
                sys_id = snap.get("data_store", "")
                for rec in snap.get("records", []):
                    if not self._record_matches(rec, all_ids):
                        continue
                    resource_id = rec.get("resource_id", "")
                    cat = _resource_category(resource_id, sys_id)
                    state = self._infer_blob_state(snap.get("collection", ""), rec)
                    facts.append(EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=cap_at,
                        system_id=sys_id,
                        resource_id=resource_id,
                        subject_user_id=resolution.user_id,
                        subject_email=resolution.input_email,
                        data_category=cat,
                        observed_state=state,
                        raw_value=json.dumps(rec)[:self._config.llm.max_evidence_chars],
                        source_span=f"snapshot:{sys_id}/{snap.get('collection','')}",
                    ))
            return facts

        # Service resource export: {service_exports:{service:{collection:[records]}}}
        if "service_exports" in data:
            exports = data["service_exports"]
            if isinstance(exports, dict):
                for svc, collections in exports.items():
                    if not isinstance(collections, dict):
                        continue
                    for coll, records in collections.items():
                        if not isinstance(records, list):
                            continue
                        for rec in records:
                            if not isinstance(rec, dict):
                                continue
                            if not self._record_matches(rec, all_ids):
                                continue
                            resource_id = rec.get("resource_id", "")
                            cat = _resource_category(resource_id, svc)
                            state = self._infer_service_export_state(coll, rec)
                            facts.append(EvidenceFact(
                                file_id=ref.file_id,
                                file_path=ref.file_path,
                                captured_at=ref.captured_at,
                                system_id=svc,
                                resource_id=resource_id,
                                subject_user_id=resolution.user_id,
                                subject_email=resolution.input_email,
                                data_category=cat,
                                observed_state=state,
                                raw_value=json.dumps(rec)[:self._config.llm.max_evidence_chars],
                                source_span=f"service_export:{svc}/{coll}",
                            ))
            return facts

        # Flat ledger / single-collection: {records:[...]} or [{...}]
        records = data if isinstance(data, list) else data.get("records", [])
        if isinstance(records, list):
            cap_at = ref.captured_at
            if isinstance(data, dict) and "captured_at" in data:
                try:
                    cap_at = _parse_utc(data["captured_at"])
                except Exception:
                    pass
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                if not self._record_matches(rec, all_ids):
                    continue
                sys_id = rec.get("system", rec.get("origin_system", ""))
                resource_id = rec.get("resource_id", "")
                result_str = rec.get("result", rec.get("status", "FOUND"))
                state = _infer_state_from_result(result_str)
                cat = _resource_category(resource_id, sys_id)
                facts.append(EvidenceFact(
                    file_id=ref.file_id,
                    file_path=ref.file_path,
                    captured_at=cap_at,
                    system_id=sys_id,
                    resource_id=resource_id,
                    subject_user_id=resolution.user_id,
                    subject_email=resolution.input_email,
                    data_category=cat,
                    observed_state=state,
                    raw_value=json.dumps(rec)[:self._config.llm.max_evidence_chars],
                    source_span="records[]",
                ))
        return facts

    @staticmethod
    def _infer_service_export_state(collection: str, rec: Dict) -> RecordState:
        """Infer state from a service_resource_export record."""
        # Profile lookups: status_code 404 → absent
        if "status_code" in rec:
            code = rec["status_code"]
            if code == 404 or rec.get("profile") is None:
                return RecordState.ABSENT
            return RecordState.PRESENT
        # Connectors: enabled field
        if "enabled" in rec:
            return RecordState.PRESENT if rec["enabled"] else RecordState.DISABLED
        # Backups: restore_allowed
        if "restore_allowed" in rec:
            return RecordState.PRESENT if rec["restore_allowed"] else RecordState.BLOCKED
        # Analytics: null identifiers → anonymized
        if all(rec.get(k) is None for k in ("user_id", "email", "phone", "email_hash")):
            if "audience_cohort" in rec or "reporting_window" in rec:
                return RecordState.ANONYMIZED
        return RecordState.PRESENT

    # ------------------------------------------------------------------
    # Log extraction
    # ------------------------------------------------------------------

    def _extract_log(
        self,
        ref: EvidenceRef,
        path: Path,
        resolution: IdentityResolution,
        all_ids: Set[str],
    ) -> List[EvidenceFact]:
        facts: List[EvidenceFact] = []
        ids_lower = {i.lower() for i in all_ids if i}
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for lineno, line in enumerate(text.splitlines(), start=1):
            line_lower = line.lower()
            if not any(i in line_lower for i in ids_lower):
                continue
            # Parse key=value structured log
            kv = self._parse_kv_log_line(line)
            resource_id = kv.get("resource_id", "")
            sys_id = kv.get("service", "")
            event = kv.get("event", "")
            result = kv.get("result", kv.get("rows", ""))

            state = self._log_event_to_state(event, result, kv)
            if state is None:
                continue

            if not resource_id or not sys_id:
                continue

            cat = _resource_category(resource_id, sys_id)
            facts.append(EvidenceFact(
                file_id=ref.file_id,
                file_path=ref.file_path,
                captured_at=ref.captured_at,
                system_id=sys_id,
                resource_id=resource_id,
                subject_user_id=resolution.user_id,
                subject_email=resolution.input_email,
                data_category=cat,
                observed_state=state,
                raw_value=line[:self._config.llm.max_evidence_chars],
                source_span=f"line:{lineno}",
            ))
        return facts

    @staticmethod
    def _parse_kv_log_line(line: str) -> Dict[str, str]:
        """Extract key=value pairs from a structured log line."""
        # Also handles key="value with spaces" and key=value
        result: Dict[str, str] = {}
        for m in re.finditer(r'(\w+)=(?:"([^"]*?)"|(\S+))', line):
            key, quoted, unquoted = m.group(1), m.group(2), m.group(3)
            result[key] = quoted if quoted is not None else unquoted
        return result

    @staticmethod
    def _log_event_to_state(event: str, result: str, kv: Dict) -> Optional[RecordState]:
        """
        Map a log event type to a RecordState.
        Returns None if the event is not useful for state determination.
        """
        event = event.lower()
        result = str(result).lower()

        if "profile_lookup_completed" in event or "record_lookup" in event:
            if result in {"0", "not_found"} or kv.get("http_status") == "404":
                return RecordState.ABSENT
            if result in {"1", "found", "identifiable"} or kv.get("http_status") == "200":
                return RecordState.PRESENT

        if "pii_scan" in event or "identity_scan" in event:
            # matched_value present means PII still in record
            if kv.get("matched_value"):
                return RecordState.PRESENT

        if "index_query_completed" in event:
            if kv.get("result") == "hit":
                return RecordState.PRESENT
            if kv.get("result") == "miss":
                return RecordState.ABSENT

        if "deletion_marker_check" in event:
            if kv.get("marker_found") == "false":
                return RecordState.PRESENT  # not deleted

        if "restore_policy_check" in event:
            blocked = kv.get("restore_blocked", kv.get("restore_allowed", ""))
            if blocked in {"true", "1"}:
                return RecordState.BLOCKED
            return RecordState.PRESENT

        if "analytics_profile_scan" in event:
            if kv.get("matched_value"):
                return RecordState.PRESENT
            return RecordState.ANONYMIZED

        return None

    # ------------------------------------------------------------------
    # PDF extraction
    # ------------------------------------------------------------------

    def _extract_pdf(
        self,
        ref: EvidenceRef,
        path: Path,
        resolution: IdentityResolution,
        all_ids: Set[str],
    ) -> List[EvidenceFact]:
        """Extract text from PDF using pdftotext, then search for identifiers."""
        try:
            result = subprocess.run(
                ["pdftotext", str(path), "-"],
                capture_output=True, text=True, timeout=30
            )
            text = result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("pdftotext failed for %s: %s", path, exc)
            return []

        ids_lower = {i.lower() for i in all_ids if i}
        if not any(i in text.lower() for i in ids_lower):
            return []

        # Build a generic fact indicating the PDF contains the user's PII
        return [EvidenceFact(
            file_id=ref.file_id,
            file_path=ref.file_path,
            captured_at=ref.captured_at,
            system_id=self._guess_system_from_origin(ref.origin),
            resource_id=self._guess_resource_from_pdf(text, ref),
            subject_user_id=resolution.user_id,
            subject_email=resolution.input_email,
            data_category=self._guess_pdf_category(ref.file_path),
            observed_state=RecordState.PRESENT,
            raw_value=text[:self._config.llm.max_evidence_chars],
            source_span="pdf:full_text",
            llm_derived=False,
        )]

    @staticmethod
    def _guess_system_from_origin(origin: str) -> str:
        """Map evidence origin string to a system_id."""
        _MAP = {
            "account_admin_portal": "account_service",
            "account_history_service": "account_service",
            "export_service": "export_service",
            "support_platform": "support_platform",
            "legal_retention_service": "legal_service",
            "security_service": "security_service",
            "search_index_service": "search_service",
            "analytics_platform": "analytics_platform",
        }
        for k, v in _MAP.items():
            if k in origin:
                return v
        return origin

    @staticmethod
    def _guess_resource_from_pdf(text: str, ref: EvidenceRef) -> str:
        """Try to extract a resource_id from PDF text, fallback to file stem."""
        # Look for known resource_id patterns in the PDF text
        for pattern in [
            r"\bsupport_\d+\b", r"\bexport_\d+\b", r"\baccount_\d+\b",
            r"\baudit_record_\d+\b", r"\blegal_hold_\d+\b",
        ]:
            m = re.search(pattern, text)
            if m:
                return m.group(0)
        return Path(ref.file_path).stem

    @staticmethod
    def _guess_pdf_category(file_path: str) -> DataCategory:
        fp = file_path.lower()
        if "support" in fp or "delivery" in fp:
            return DataCategory.SUPPORT_ATTACHMENT
        if "legal" in fp or "retention" in fp:
            return DataCategory.LEGAL_HOLD_RECORD
        if "security" in fp or "compliance" in fp:
            return DataCategory.SECURITY_AUDIT_LOG
        return DataCategory.SUPPORT_ATTACHMENT

    # ------------------------------------------------------------------
    # Image extraction (LLM vision)
    # ------------------------------------------------------------------

    def _extract_image(
        self,
        ref: EvidenceRef,
        path: Path,
        resolution: IdentityResolution,
        all_ids: Set[str],
    ) -> List[EvidenceFact]:
        """Use the deterministic image catalogue as the no-LLM fallback.

        Image content is never sent to a hosted service and the legacy free-form
        vision path is intentionally disabled.  If a future OCR adapter is
        added, it must feed the bounded Ollama extractor rather than authoring
        EvidenceFacts directly.
        """
        from .evidence_ingestion.image_reader import IMAGE_CATALOGUE

        identifiers = {str(value).lower() for value in all_ids if value}
        facts: List[EvidenceFact] = []
        for descriptor in IMAGE_CATALOGUE.get(ref.file_id, []):
            description = str(descriptor.get("description", ""))
            if identifiers and not any(identifier in description.lower() for identifier in identifiers):
                continue
            try:
                category = DataCategory(descriptor["data_category_str"])
                state = RecordState(descriptor["state_str"])
            except (KeyError, ValueError):
                continue
            facts.append(EvidenceFact(
                file_id=ref.file_id,
                file_path=ref.file_path,
                captured_at=ref.captured_at,
                system_id=str(descriptor["system_id"]),
                resource_id=str(descriptor["resource_id"]),
                subject_user_id=resolution.user_id,
                subject_email=resolution.input_email,
                data_category=category,
                observed_state=state,
                raw_value=description,
                source_span="image:catalogue",
                llm_derived=False,
                llm_confidence=LLMConfidence.NA,
                needs_review=True,
            ))
        return facts

    # ------------------------------------------------------------------
    # TXT extraction (shift handover)
    # ------------------------------------------------------------------

    def _extract_txt(
        self,
        ref: EvidenceRef,
        path: Path,
        resolution: IdentityResolution,
        all_ids: Set[str],
    ) -> List[EvidenceFact]:
        """Parse shift handover line format:
        timestamp | system | resource_id | record_type | status | subject_key
        """
        facts: List[EvidenceFact] = []
        ids_lower = {i.lower() for i in all_ids if i}
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []

        for lineno, line in enumerate(lines, start=1):
            if "|" not in line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 6:
                continue
            ts_str, sys_id, resource_id, record_type, status, subject_key = (
                parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
            )
            if subject_key.lower() not in ids_lower:
                continue
            state = _infer_state_from_result(status)
            cat = _resource_category(resource_id, sys_id)
            facts.append(EvidenceFact(
                file_id=ref.file_id,
                file_path=ref.file_path,
                captured_at=ref.captured_at,
                system_id=sys_id,
                resource_id=resource_id,
                subject_user_id=resolution.user_id,
                subject_email=resolution.input_email,
                data_category=cat,
                observed_state=state,
                raw_value=line[:self._config.llm.max_evidence_chars],
                source_span=f"line:{lineno}",
            ))
        return facts
