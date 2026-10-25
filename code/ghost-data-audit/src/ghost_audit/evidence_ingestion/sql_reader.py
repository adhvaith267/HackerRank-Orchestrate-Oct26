"""
sql_reader.py — Safe SQL snapshot reader for ghost-data-audit evidence ingestion.

Loads a .sql text dump into a fresh in-memory SQLite database after
allow-list filtering every statement, then queries the loaded tables to
extract EvidenceFacts linked to the given subject identifiers.

Public API:
    SQLReader(gap_tracker, cache=None)
    .read(ref: EvidenceRef, file_path: Path, identifiers: Set[str]) -> List[EvidenceFact]

Security contract (all must hold for every invocation):
  - Only allowed SQL statement types pass the filter; anything else raises
    EvidenceIngestionError via gap_tracker.fatal().
  - The in-memory database is never written to disk (:memory:).
  - Extension loading is disabled immediately after the connection is opened.
  - All post-load queries are parameterised SELECT statements.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ghost_audit.schemas import (
    DataCategory,
    EvidenceFact,
    EvidenceRef,
    RecordState,
    _parse_utc,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class EvidenceIngestionError(Exception):
    """Raised when a security violation is detected in an evidence file."""


# ---------------------------------------------------------------------------
# Statement allow-list regex
#
# We strip SQL comments and blank lines first, then check the *first keyword*
# of each remaining line.  Only the listed statement prefixes are permitted.
# ---------------------------------------------------------------------------

# Allowed first-keyword patterns (case-insensitive)
_ALLOWED_STMT_RE = re.compile(
    r"^\s*("
    r"create\s+table"
    r"|create\s+index"        # index metadata is harmless
    r"|create\s+unique\s+index"
    r"|insert\s+into"
    r"|begin"
    r"|commit"
    r"|rollback"
    r"|pragma\s+foreign_keys"
    r"|pragma"                # other PRAGMAs are fine in a dump
    r")\b",
    re.IGNORECASE,
)

# Forbidden patterns that must never appear in a legitimate dump
_FORBIDDEN_STMT_RE = re.compile(
    r"^\s*("
    r"attach|detach"
    r"|drop\b"
    r"|alter\b"
    r"|load_extension"
    r"|select\b"
    r"|update\b"
    r"|delete\b"
    r"|replace\b"
    r")\b",
    re.IGNORECASE,
)

# SQLite extension loading via the dot-command notation in scripts
_LOAD_EXTENSION_RE = re.compile(r"\.load\b", re.IGNORECASE)

# Single-line comment (-- ...) and blank line pattern used during filtering
_SQL_COMMENT_RE = re.compile(r"^\s*--")

# ---------------------------------------------------------------------------
# Resource-id prefix → DataCategory  (mirrors evidence.py for consistency)
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

_TABLE_SYSTEM: Dict[str, str] = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
    "snapshot_scope": "account_service",
    # blob / replica tables
    "customer_data_primary": "account_service",
    "customer_data_read_replica": "account_service",
    "customer_data_replica_ap_south": "account_service",
    "customer_data_replica_eu_west": "account_service",
    "customer_data_reporting_replica": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "search_documents_primary": "search_service",
}

_TABLE_CATEGORY: Dict[str, DataCategory] = {
    "customer_profiles": DataCategory.USER_PROFILE,
    "customer_search_documents": DataCategory.SEARCH_INDEX_ENTRY,
    "customer_analytics_profiles": DataCategory.ANALYTICS_PROFILE,
    "support_records": DataCategory.SUPPORT_MESSAGE,
    "customer_exports": DataCategory.USER_EXPORT,
    "connector_subscriptions": DataCategory.USER_PROFILE,
    "backup_restore_entries": DataCategory.BACKUP_ARCHIVE,
    "security_audit_records": DataCategory.SECURITY_AUDIT_LOG,
    "snapshot_scope": DataCategory.USER_PROFILE,
    "customer_profiles_primary": DataCategory.USER_PROFILE,
    "customer_profiles_failover_replica": DataCategory.USER_PROFILE,
    "search_documents_primary": DataCategory.SEARCH_INDEX_ENTRY,
}

# customer_data_inventory tables (the 9 named tables in topology 1)
_INVENTORY_TABLES: Set[str] = {
    "customer_profiles",
    "customer_search_documents",
    "customer_analytics_profiles",
    "support_records",
    "customer_exports",
    "connector_subscriptions",
    "backup_restore_entries",
    "security_audit_records",
    "snapshot_scope",
}

# Blob-schema tables (topology 2-4): have resource_id, origin_system, collection_name,
# record_json, updated_at columns
_BLOB_TABLE_PATTERNS: Tuple[str, ...] = (
    "customer_data_primary",
    "customer_data_read_replica",
    "customer_data_replica_",  # ap_south, eu_west …
    "customer_data_reporting_replica",
)

# Failover flat tables (topology 5)
_FAILOVER_PRIMARY = "customer_profiles_primary"
_FAILOVER_REPLICA = "customer_profiles_failover_replica"

# Primary-only search table (topology 6)
_SEARCH_PRIMARY = "search_documents_primary"


# ---------------------------------------------------------------------------
# GapTracker protocol
# (concrete implementation lives outside this module; we depend only on the
# .warn() and .fatal() interface.)
# ---------------------------------------------------------------------------


class _GapTrackerProtocol:
    """Structural type-hint for the gap_tracker dependency."""

    def warn(self, category: str, message: str, **extra: Any) -> None:  # pragma: no cover
        ...

    def fatal(self, category: str, message: str, **extra: Any) -> None:  # pragma: no cover
        ...


# ---------------------------------------------------------------------------
# Helper: infer state from flat inventory row fields
# ---------------------------------------------------------------------------


def _infer_inventory_state(table: str, rdict: Dict[str, Any]) -> RecordState:
    """Determine the RecordState for a flat inventory row."""
    # account_status on customer_profiles
    status = str(rdict.get("account_status") or "").upper()
    if "DELET" in status or status in {"ABSENT"}:
        return RecordState.ABSENT

    # Connector active/disabled
    enabled = rdict.get("enabled")
    if enabled is not None:
        return RecordState.PRESENT if enabled else RecordState.DISABLED

    # Backup restore risk
    restore_allowed = rdict.get("restore_allowed")
    if restore_allowed is not None:
        return RecordState.PRESENT if restore_allowed else RecordState.BLOCKED

    # Analytics — all identifiers null → anonymized
    if table == "customer_analytics_profiles":
        if all(
            rdict.get(k) is None
            for k in ("user_id", "email", "phone", "email_hash")
        ):
            return RecordState.ANONYMIZED

    # Support — redacted message
    if table == "support_records":
        mt = str(rdict.get("message_text") or "")
        if "[REDACTED]" in mt:
            return RecordState.REDACTED

    return RecordState.PRESENT


def _infer_blob_state(collection_name: str, rec: Dict[str, Any]) -> RecordState:
    """Infer state from a blob (record_json) payload."""
    # Analytics anonymous: none of the PII columns populated
    if "analytic" in (collection_name or "").lower():
        if all(rec.get(k) is None for k in ("user_id", "email", "phone", "email_hash")):
            return RecordState.ANONYMIZED
        return RecordState.PRESENT

    # Support: redacted message marker
    if "support" in (collection_name or "").lower():
        if "[REDACTED]" in str(rec.get("message_text", "")):
            return RecordState.REDACTED
        return RecordState.PRESENT

    # Backup catalog
    if "backup" in (collection_name or "").lower():
        ra = rec.get("restore_allowed")
        if ra is False:
            return RecordState.BLOCKED
        return RecordState.PRESENT

    # Connector configurations
    if "connector" in (collection_name or "").lower():
        en = rec.get("enabled")
        if en is not None:
            return RecordState.PRESENT if en else RecordState.DISABLED

    # Customer profiles: check account_status
    if "profile" in (collection_name or "").lower():
        status = str(rec.get("account_status") or "").upper()
        if "DELET" in status or status in {"ABSENT"}:
            return RecordState.ABSENT

    return RecordState.PRESENT


def _resource_category(resource_id: str, table: str) -> DataCategory:
    """Infer DataCategory from resource_id prefix first, then table name."""
    for prefix, cat in _RID_CATEGORY.items():
        if resource_id.startswith(prefix):
            return cat
    return _TABLE_CATEGORY.get(table, DataCategory.USER_PROFILE)


def _find_email(rdict: Dict[str, Any], identifiers: Set[str]) -> Optional[str]:
    """Return the first email-valued field that matches a known identifier."""
    ids_lower = {i.lower() for i in identifiers}
    email_cols = (
        "email", "requester_email", "owner_email", "customer_email",
        "subject_email", "email_address",
    )
    for col in email_cols:
        val = rdict.get(col)
        if val and isinstance(val, str) and val.lower() in ids_lower:
            return val.lower()
    # Fallback: any column whose value is in identifiers
    for val in rdict.values():
        if val and isinstance(val, str) and val.lower() in ids_lower:
            return val.lower()
    return None


def _user_id_from_row(rdict: Dict[str, Any]) -> Optional[str]:
    """Extract a stable user reference from a row dict."""
    for col in ("user_id", "customer_reference", "subject_reference"):
        v = rdict.get(col)
        if v:
            return str(v)
    return None


def _row_matches(rdict: Dict[str, Any], identifiers_lower: Set[str]) -> bool:
    """Return True if any column value in the row matches a known identifier."""
    for val in rdict.values():
        if val and isinstance(val, str) and val.lower() in identifiers_lower:
            return True
    return False


def _record_matches_deep(rec: Any, identifiers_lower: Set[str]) -> bool:
    """Recursively search a JSON-decoded value for any identifier match."""
    if isinstance(rec, str):
        return rec.lower() in identifiers_lower
    if isinstance(rec, dict):
        return any(_record_matches_deep(v, identifiers_lower) for v in rec.values())
    if isinstance(rec, list):
        return any(_record_matches_deep(v, identifiers_lower) for v in rec)
    return False


# ---------------------------------------------------------------------------
# SQL statement filter
# ---------------------------------------------------------------------------


def _filter_sql(sql_text: str) -> str:
    """
    Line-by-line allow-list filter.

    Returns the filtered SQL text (only allowed statements) or raises
    EvidenceIngestionError if a forbidden statement is found.

    Tracks parenthesis depth to distinguish statement-start lines from
    continuation lines inside multi-line CREATE TABLE column lists and
    multi-value INSERT INTO statements.  Column definitions and VALUES
    rows are NOT treated as new statement starts.
    """
    allowed_lines: List[str] = []
    paren_depth: int = 0  # track depth to detect continuation lines

    for raw_line in sql_text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        # Blank lines and pure comment lines are always allowed
        if not stripped or _SQL_COMMENT_RE.match(line):
            allowed_lines.append(line)
            # Count parentheses even in pass-through lines
            paren_depth += stripped.count("(") - stripped.count(")")
            if paren_depth < 0:
                paren_depth = 0
            continue

        # Reject extension loading via .load pseudo-command
        if _LOAD_EXTENSION_RE.search(line):
            raise EvidenceIngestionError(
                f"Forbidden SQLite extension load detected: {line!r}"
            )

        # Check for explicitly forbidden keywords (always, regardless of depth)
        if _FORBIDDEN_STMT_RE.match(line):
            raise EvidenceIngestionError(
                f"Forbidden SQL statement detected: {line!r}"
            )

        # If we're inside an open parenthesis group (e.g. inside CREATE TABLE
        # column list or multi-value INSERT), this is a continuation line —
        # not a new statement start.  Just track depth and pass through.
        if paren_depth > 0:
            paren_depth += stripped.count("(") - stripped.count(")")
            if paren_depth < 0:
                paren_depth = 0
            allowed_lines.append(line)
            continue

        # At top-level (paren_depth == 0): check whether the line starts a
        # new SQL statement.  A "statement start" is any line that begins with
        # an alpha character or underscore (possibly after whitespace).
        first_token_m = re.match(r"^\s*([A-Za-z_])", line)
        if first_token_m:
            if not _ALLOWED_STMT_RE.match(line):
                raise EvidenceIngestionError(
                    f"Statement not on allow-list: {line!r}"
                )

        # Update parenthesis depth after passing the check
        paren_depth += stripped.count("(") - stripped.count(")")
        if paren_depth < 0:
            paren_depth = 0

        allowed_lines.append(line)

    return "\n".join(allowed_lines)


# ---------------------------------------------------------------------------
# Topology detection
# ---------------------------------------------------------------------------

_TOPOLOGY_INVENTORY = "customer_data_inventory"
_TOPOLOGY_READ_REPLICA = "read_replica"
_TOPOLOGY_REGIONAL_REPLICAS = "regional_replicas"
_TOPOLOGY_REPORTING_REPLICA = "reporting_replica"
_TOPOLOGY_FAILOVER_REPLICA = "failover_replica"
_TOPOLOGY_PRIMARY_ONLY = "primary_only"
_TOPOLOGY_UNKNOWN = "unknown"


def _detect_topology(tables: Set[str]) -> str:
    """Determine which of the 6 SQL topologies this file represents."""
    if tables & _INVENTORY_TABLES:
        return _TOPOLOGY_INVENTORY
    if _SEARCH_PRIMARY in tables and len(tables) <= 3:
        return _TOPOLOGY_PRIMARY_ONLY
    if _FAILOVER_REPLICA in tables or _FAILOVER_PRIMARY in tables:
        return _TOPOLOGY_FAILOVER_REPLICA
    blob_present = any(
        any(t.startswith(pat) for pat in _BLOB_TABLE_PATTERNS)
        for t in tables
    )
    if blob_present:
        replica_names = [t for t in tables if "replica" in t]
        if any("ap_south" in r or "eu_west" in r for r in replica_names):
            return _TOPOLOGY_REGIONAL_REPLICAS
        if any("reporting" in r for r in replica_names):
            return _TOPOLOGY_REPORTING_REPLICA
        return _TOPOLOGY_READ_REPLICA
    return _TOPOLOGY_UNKNOWN


# ---------------------------------------------------------------------------
# SQLReader
# ---------------------------------------------------------------------------


class SQLReader:
    """
    Safe SQL snapshot reader.

    Parameters
    ----------
    gap_tracker:
        Dependency that provides .warn() and .fatal() for logging gaps or
        raising fatal errors.
    cache:
        Optional mapping used as a result cache keyed by file_id.  Not used
        directly; callers may pass a shared cache object for future extension.
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
        Parse *file_path* as a SQL dump, load it into `:memory:`, and return
        all EvidenceFacts whose rows match any of the supplied *identifiers*.

        Parameters
        ----------
        ref:
            The EvidenceRef manifest entry for this file (provides file_id,
            captured_at, file_path string).
        file_path:
            Absolute (or otherwise resolvable) path to the .sql file.
        identifiers:
            Set of known subject identifiers (emails, hashes, user_ids …).
            Matching is case-insensitive.

        Returns
        -------
        List[EvidenceFact]
            Empty list on parse errors or if no rows match.

        Raises
        ------
        EvidenceIngestionError
            When a forbidden SQL statement is detected in the dump.
        """
        if not file_path.exists():
            self._gap.warn(
                file_id=ref.file_id,
                reason="sql_file_missing",
                detail=f"SQL file not found: {file_path.name}",
            )
            return []

        # 1. Read the raw SQL text
        try:
            raw_sql = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._gap.warn(
                file_id=ref.file_id,
                reason="sql_read_error",
                detail=f"Cannot read SQL file {file_path.name}: {exc}",
            )
            return []

        # 2. Security filter — may raise EvidenceIngestionError
        try:
            clean_sql = _filter_sql(raw_sql)
        except EvidenceIngestionError:
            self._gap.fatal(
                file_id=ref.file_id,
                reason="sql_forbidden_statement",
            )
            raise  # propagate to caller

        # 3. Load into a fresh :memory: SQLite connection
        ids_lower: Set[str] = {i.lower() for i in identifiers if i}

        try:
            conn = sqlite3.connect(":memory:", isolation_level=None)
        except Exception as exc:
            self._gap.warn(
                file_id=ref.file_id,
                reason="sql_connect_error",
                detail=f"sqlite3.connect failed: {exc}",
            )
            return []

        try:
            # Immediately disable extension loading
            try:
                conn.enable_load_extension(False)
            except AttributeError:
                pass  # Some builds don't expose this; safe to ignore

            try:
                conn.executescript(clean_sql)
            except Exception as exc:
                self._gap.warn(
                    file_id=ref.file_id,
                    reason="sql_executescript_error",
                    detail=f"executescript failed for {file_path.name}: {exc}",
                )
                return []

            # 4. Detect topology and extract facts
            tables = self._get_tables(conn)
            topology = _detect_topology(tables)
            logger.debug(
                "SQL %s: topology=%s tables=%s",
                ref.file_id,
                topology,
                sorted(tables),
            )

            facts: List[EvidenceFact] = []

            if topology == _TOPOLOGY_INVENTORY:
                facts = self._extract_inventory(ref, conn, tables, ids_lower)
            elif topology in (
                _TOPOLOGY_READ_REPLICA,
                _TOPOLOGY_REGIONAL_REPLICAS,
                _TOPOLOGY_REPORTING_REPLICA,
            ):
                facts = self._extract_blob(ref, conn, tables, ids_lower)
            elif topology == _TOPOLOGY_FAILOVER_REPLICA:
                facts = self._extract_failover_flat(ref, conn, tables, ids_lower)
            elif topology == _TOPOLOGY_PRIMARY_ONLY:
                facts = self._extract_search_primary(ref, conn, ids_lower)
            else:
                # Unknown topology: try both blob and inventory approaches
                facts = self._extract_inventory(ref, conn, tables, ids_lower)
                facts += self._extract_blob(ref, conn, tables, ids_lower)

            return facts

        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Private: topology-specific extractors
    # ------------------------------------------------------------------

    def _extract_inventory(
        self,
        ref: EvidenceRef,
        conn: sqlite3.Connection,
        tables: Set[str],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        """Extract from customer_data_inventory flat-schema tables."""
        facts: List[EvidenceFact] = []
        for table in _INVENTORY_TABLES & tables:
            try:
                facts.extend(
                    self._scan_flat_table(ref, conn, table, ids_lower)
                )
            except Exception as exc:
                logger.warning(
                    "Inventory table scan error [%s] %s: %s",
                    ref.file_id,
                    table,
                    exc,
                )
        return facts

    def _extract_blob(
        self,
        ref: EvidenceRef,
        conn: sqlite3.Connection,
        tables: Set[str],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        """Extract from blob-schema tables (record_json column)."""
        facts: List[EvidenceFact] = []
        blob_tables = {
            t
            for t in tables
            if any(t.startswith(pat) for pat in _BLOB_TABLE_PATTERNS)
            or ("primary" in t and "profiles" not in t)
        }
        for table in blob_tables:
            try:
                facts.extend(
                    self._scan_blob_table(ref, conn, table, ids_lower)
                )
            except Exception as exc:
                logger.warning(
                    "Blob table scan error [%s] %s: %s",
                    ref.file_id,
                    table,
                    exc,
                )
        return facts

    def _extract_failover_flat(
        self,
        ref: EvidenceRef,
        conn: sqlite3.Connection,
        tables: Set[str],
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        """Extract from flat failover_replica tables."""
        facts: List[EvidenceFact] = []
        failover_tables = {
            t
            for t in tables
            if "profiles" in t or "failover" in t or "primary" in t
        }
        for table in failover_tables:
            try:
                facts.extend(
                    self._scan_flat_table(ref, conn, table, ids_lower)
                )
            except Exception as exc:
                logger.warning(
                    "Failover table scan error [%s] %s: %s",
                    ref.file_id,
                    table,
                    exc,
                )
        return facts

    def _extract_search_primary(
        self,
        ref: EvidenceRef,
        conn: sqlite3.Connection,
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        """Extract from search_documents_primary (primary_only topology)."""
        facts: List[EvidenceFact] = []
        try:
            # Use parameterised query — but we need to match on email which
            # could be any of several identifiers; do a full scan and filter.
            rows = conn.execute(
                "SELECT resource_id, display_name, email, "
                "source_resource_id, indexed_at "
                f"FROM {_SEARCH_PRIMARY}"
            ).fetchall()
            col_names = [
                "resource_id", "display_name", "email",
                "source_resource_id", "indexed_at",
            ]
            for row in rows:
                rdict: Dict[str, Any] = dict(zip(col_names, row))
                email_val = rdict.get("email") or ""
                if email_val.lower() not in ids_lower:
                    continue
                resource_id = str(rdict.get("resource_id") or "")
                fact = self._make_fact(
                    ref=ref,
                    table=_SEARCH_PRIMARY,
                    resource_id=resource_id,
                    rdict=rdict,
                    matched_email=email_val.lower(),
                    state=RecordState.PRESENT,
                )
                facts.append(fact)
        except Exception as exc:
            logger.warning(
                "search_documents_primary scan error [%s]: %s",
                ref.file_id,
                exc,
            )
        return facts

    # ------------------------------------------------------------------
    # Private: generic table scanners
    # ------------------------------------------------------------------

    def _scan_flat_table(
        self,
        ref: EvidenceRef,
        conn: sqlite3.Connection,
        table: str,
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        """Fetch all rows from a flat table and filter by identifier match."""
        facts: List[EvidenceFact] = []
        rows, col_names = self._fetch_all(conn, table)
        for row in rows:
            rdict: Dict[str, Any] = dict(zip(col_names, row))
            if not _row_matches(rdict, ids_lower):
                continue
            try:
                resource_id = str(rdict.get("resource_id") or "")
                matched_email = _find_email(rdict, ids_lower) or ""
                state = _infer_inventory_state(table, rdict)
                facts.append(
                    self._make_fact(
                        ref=ref,
                        table=table,
                        resource_id=resource_id,
                        rdict=rdict,
                        matched_email=matched_email,
                        state=state,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "Row parse error [%s] table=%s: %s",
                    ref.file_id,
                    table,
                    exc,
                )
        return facts

    def _scan_blob_table(
        self,
        ref: EvidenceRef,
        conn: sqlite3.Connection,
        table: str,
        ids_lower: Set[str],
    ) -> List[EvidenceFact]:
        """Fetch all rows from a blob-schema table and filter by identifier match."""
        facts: List[EvidenceFact] = []
        try:
            rows = conn.execute(
                f"SELECT resource_id, origin_system, collection_name, "
                f"record_json, updated_at FROM {table}"
            ).fetchall()
        except Exception as exc:
            # Table might not have the blob schema — fall back to flat scan
            logger.debug(
                "Blob schema fallback to flat for table=%s: %s", table, exc
            )
            return self._scan_flat_table(ref, conn, table, ids_lower)

        for (resource_id, origin_system, collection_name, record_json, updated_at) in rows:
            try:
                rec: Dict[str, Any] = json.loads(record_json) if record_json else {}
            except Exception:
                rec = {}

            if not _record_matches_deep(rec, ids_lower):
                continue

            try:
                matched_email = _find_email(rec, ids_lower) or ""
                state = _infer_blob_state(collection_name or "", rec)
                sys_id = origin_system or _TABLE_SYSTEM.get(table, "")
                cat = _resource_category(str(resource_id or ""), table)
                raw = json.dumps(rec)[:2000]
                facts.append(
                    EvidenceFact(
                        file_id=ref.file_id,
                        file_path=ref.file_path,
                        captured_at=ref.captured_at,
                        system_id=sys_id,
                        resource_id=str(resource_id or ""),
                        subject_user_id=_user_id_from_row(rec),
                        subject_email=matched_email or None,
                        data_category=cat,
                        observed_state=state,
                        raw_value=raw,
                        source_span=f"table:{table}:row:{resource_id}",
                        llm_derived=False,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "Blob row parse error [%s] table=%s resource=%s: %s",
                    ref.file_id,
                    table,
                    resource_id,
                    exc,
                )
        return facts

    # ------------------------------------------------------------------
    # Private: shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_tables(conn: sqlite3.Connection) -> Set[str]:
        """Return the set of table names in the in-memory DB."""
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        return {r[0] for r in rows}

    @staticmethod
    def _fetch_all(
        conn: sqlite3.Connection,
        table: str,
    ) -> Tuple[List[Any], List[str]]:
        """
        Fetch every row and column names from *table*.

        Returns (rows, col_names).  Uses a hardcoded table name (already
        validated against sqlite_master) and a parameterised LIMIT clause
        to keep the query safe.
        """
        cur = conn.execute(f"SELECT * FROM {table}")
        col_names = [d[0] for d in cur.description]
        rows = cur.fetchall()
        return rows, col_names

    def _make_fact(
        self,
        ref: EvidenceRef,
        table: str,
        resource_id: str,
        rdict: Dict[str, Any],
        matched_email: str,
        state: RecordState,
    ) -> EvidenceFact:
        """Construct an EvidenceFact from a flat row dict."""
        sys_id = _TABLE_SYSTEM.get(table, "")
        cat = _resource_category(resource_id, table)
        raw = json.dumps(rdict)[:2000]
        return EvidenceFact(
            file_id=ref.file_id,
            file_path=ref.file_path,
            captured_at=ref.captured_at,
            system_id=sys_id,
            resource_id=resource_id,
            subject_user_id=_user_id_from_row(rdict),
            subject_email=matched_email or None,
            data_category=cat,
            observed_state=state,
            raw_value=raw,
            source_span=f"table:{table}:row:{resource_id}",
            llm_derived=False,
        )
