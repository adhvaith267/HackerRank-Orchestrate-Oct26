"""
log_reader.py — Structured log reader.

Public API:
    LogReader(gap_tracker, cache=None)
    .read(ref: EvidenceRef, file_path: Path, identifiers: Set[str]) -> List[EvidenceFact]

Handles the key=value structured log format observed across all service logs:
    2026-09-15T08:51:43Z level=DEBUG service=account_service event=... resource_id=... rows=0 ...

State is inferred from the event + result combination per DATA_DISCOVERY.md rules.
PII values that match any supplied identifier are redacted in raw_value.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from ghost_audit.schemas import DataCategory, EvidenceFact, EvidenceRef, RecordState, _parse_utc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Matches ISO-8601 datetime as the leading token, e.g. 2026-09-15T08:51:43Z
_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
)

# Matches key=value pairs; value may be quoted or unquoted
# e.g.  service=account_service   event="profile_lookup_completed"
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')

# Fields we extract from each log line
_FIELDS_OF_INTEREST = {
    "service", "resource_id", "event", "result", "rows", "http_status",
    "enabled", "restore_blocked", "matched_value", "marker_found",
    "subject_ref", "subject_reference", "seq", "system", "record_type",
    "customer_reference", "lookup_key",
}


# ---------------------------------------------------------------------------
# State inference
# ---------------------------------------------------------------------------

def _infer_state(kv: Dict[str, str]) -> Optional[RecordState]:
    """
    Return the RecordState implied by the log line's event + result fields,
    or None if no rule matches (line will be skipped).
    """
    event = kv.get("event", "").lower()
    result = kv.get("result", "").lower()
    rows_raw = kv.get("rows", "")
    http_status = kv.get("http_status", "")
    enabled = kv.get("enabled", "").lower()
    marker_found = kv.get("marker_found", "").lower()

    # --- profile_lookup_completed ----------------------------------------
    if event == "profile_lookup_completed":
        if rows_raw == "0" or http_status == "404":
            return RecordState.ABSENT
        if rows_raw == "1":
            return RecordState.PRESENT
        # rows present but value not 0/1 — still PRESENT
        if rows_raw:
            try:
                if int(rows_raw) > 0:
                    return RecordState.PRESENT
            except ValueError:
                pass
        return None

    # --- PII / identity scans --------------------------------------------
    if event in ("message_pii_scan", "analytics_identity_scan", "attachment_pii_scan"):
        if kv.get("matched_value"):
            return RecordState.PRESENT
        return None

    # --- index_query_completed -------------------------------------------
    if event == "index_query_completed":
        if result == "hit":
            return RecordState.PRESENT
        if result == "miss":
            return RecordState.ABSENT
        return None

    # --- connector_config_read_completed ---------------------------------
    if event == "connector_config_read_completed":
        if enabled == "true":
            return RecordState.PRESENT   # active data flow
        if enabled == "false":
            return RecordState.DISABLED
        return None

    # --- deletion_marker_check -------------------------------------------
    if event == "deletion_marker_check":
        if marker_found == "false":
            return RecordState.PRESENT   # no deletion marker → still present
        if marker_found == "true":
            return RecordState.ABSENT    # marker found → deleted
        return None

    # --- restore_policy_check -------------------------------------------
    if event == "restore_policy_check":
        if result == "blocked":
            return RecordState.BLOCKED
        if result == "active":
            return RecordState.PRESENT
        return None

    # --- record_lookup (search_index_diagnostic format) ------------------
    if event == "record_lookup":
        mapping = {
            "found": RecordState.PRESENT,
            "not_found": RecordState.ABSENT,
            "identifiable": RecordState.PRESENT,
            "anonymized": RecordState.ANONYMIZED,
            "active": RecordState.PRESENT,
            "blocked": RecordState.BLOCKED,
        }
        if result in mapping:
            return mapping[result]
        return None

    # --- generic export / other events that imply existence --------------
    if event in (
        "export_started", "export_completed", "export_ready",
        "record_found", "lookup_completed",
    ):
        return RecordState.PRESENT

    return None


# ---------------------------------------------------------------------------
# PII redaction helper
# ---------------------------------------------------------------------------

def _redact_line(line: str, identifiers_lower: Set[str]) -> str:
    """
    Replace every occurrence of an identifier value (case-insensitive) in *line*
    with '[PII_REDACTED]'.  Returns the redacted string.
    """
    result = line
    for ident in identifiers_lower:
        if not ident:
            continue
        # Case-insensitive replacement
        pattern = re.compile(re.escape(ident), re.IGNORECASE)
        result = pattern.sub("[PII_REDACTED]", result)
    return result


# ---------------------------------------------------------------------------
# LogReader
# ---------------------------------------------------------------------------

class LogReader:
    """
    Reads a structured key=value service log and returns EvidenceFacts.

    One fact is produced per log line that:
      1. Contains at least one of the caller-supplied identifiers (case-insensitive).
      2. Has a determinable RecordState from the event+result rules.

    PII is always redacted from raw_value.
    """

    def __init__(self, gap_tracker, cache=None) -> None:
        # gap_tracker: GapTracker instance (imported lazily to avoid circular import)
        # cache: ExtractionCache (unused for logs — kept for API symmetry)
        self._gap = gap_tracker
        self._cache = cache  # not used for log files

    def read(
        self,
        ref: EvidenceRef,
        file_path: Path,
        identifiers: Set[str],
    ) -> List[EvidenceFact]:
        """
        Parse *file_path* and return facts relevant to any of *identifiers*.

        Parameters
        ----------
        ref:         EvidenceRef manifest row for this file.
        file_path:   Absolute path to the log file on disk.
        identifiers: Set of identifier strings for the subject
                     (emails, user_ids, hashes, resource IDs, etc.).

        Returns
        -------
        List of EvidenceFact, one per matching + state-bearing log line,
        in file order (deterministic).
        """
        if not identifiers:
            return []

        identifiers_lower: Set[str] = {i.lower() for i in identifiers if i}

        facts: List[EvidenceFact] = []

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            self._gap.warn(
                file_id=ref.file_id,
                reason="log_unreadable",
                detail=str(exc),
            )
            return []

        for lineno, raw_line in enumerate(lines, start=1):
            line_lower = raw_line.lower()

            # Fast pre-filter: skip lines that contain none of the identifiers
            if not any(ident in line_lower for ident in identifiers_lower):
                continue

            # ----------------------------------------------------------------
            # Parse leading timestamp
            # ----------------------------------------------------------------
            captured_at = ref.captured_at  # default fallback
            ts_match = _TS_RE.match(raw_line.strip())
            if ts_match:
                try:
                    captured_at = _parse_utc(ts_match.group(1))
                except ValueError:
                    pass

            # ----------------------------------------------------------------
            # Parse all key=value pairs
            # ----------------------------------------------------------------
            kv: Dict[str, str] = {}
            for m in _KV_RE.finditer(raw_line):
                key = m.group(1).lower()
                value = m.group(2) if m.group(2) is not None else m.group(3)
                if key in _FIELDS_OF_INTEREST:
                    kv[key] = value

            # ----------------------------------------------------------------
            # Determine state
            # ----------------------------------------------------------------
            state = _infer_state(kv)
            if state is None:
                continue  # no determinable state → skip line

            # ----------------------------------------------------------------
            # Build redacted raw_value
            # ----------------------------------------------------------------
            redacted_line = _redact_line(raw_line, identifiers_lower)

            # ----------------------------------------------------------------
            # Resolve subject identifiers from matched line
            # ----------------------------------------------------------------
            subject_email: Optional[str] = None
            subject_user_id: Optional[str] = None
            for ident in identifiers_lower:
                if "@" in ident and ident in line_lower:
                    subject_email = ident
                if re.match(r"^user_\d+$", ident) and ident in line_lower:
                    subject_user_id = ident

            # ----------------------------------------------------------------
            # Resolve system_id and resource_id from kv
            # ----------------------------------------------------------------
            system_id = kv.get("service") or ref.origin or "unknown_service"
            resource_id = (
                kv.get("resource_id")
                or kv.get("system")
                or ref.file_id
            )

            fact = EvidenceFact(
                file_id=ref.file_id,
                file_path=ref.file_path,
                captured_at=captured_at,
                system_id=system_id,
                resource_id=resource_id,
                subject_user_id=subject_user_id,
                subject_email=subject_email,
                data_category=None,   # caller enriches if needed
                observed_state=state,
                raw_value=redacted_line[:500],  # truncate for safety
                source_span=f"line:{lineno}",
                llm_derived=False,
                needs_review=False,
            )
            facts.append(fact)

        logger.debug(
            "LogReader[%s]: %d matching facts from %d lines",
            ref.file_id,
            len(facts),
            len(lines),
        )
        return facts
