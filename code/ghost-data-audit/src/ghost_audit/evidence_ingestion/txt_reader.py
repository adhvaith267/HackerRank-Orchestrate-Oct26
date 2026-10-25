"""
txt_reader.py — Plain-text evidence reader (shift handover documents).

Public API:
    TXTReader(gap_tracker, cache=None)
    .read(ref: EvidenceRef, file_path: Path, identifiers: Set[str]) -> List[EvidenceFact]

Format: pipe-delimited lines:
    timestamp | system_id | resource_id | record_type | status | subject_key

Lines with fewer than 6 pipe-separated fields or no '|' character are skipped
(header rows and free-text sections are automatically ignored).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional, Set

from ghost_audit.schemas import DataCategory, EvidenceFact, EvidenceRef, RecordState, _parse_utc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Status → RecordState mapping
# ---------------------------------------------------------------------------

_STATUS_STATE_MAP = {
    "found":         RecordState.PRESENT,
    "identifiable":  RecordState.PRESENT,
    "active":        RecordState.PRESENT,
    "not_found":     RecordState.ABSENT,
    "anonymized":    RecordState.ANONYMIZED,
    "anonymised":    RecordState.ANONYMIZED,   # British spelling variant
    "blocked":       RecordState.BLOCKED,
    "disabled":      RecordState.DISABLED,
    "redacted":      RecordState.REDACTED,
}

# ---------------------------------------------------------------------------
# TXTReader
# ---------------------------------------------------------------------------

class TXTReader:
    """
    Reads pipe-delimited shift handover documents and returns EvidenceFacts
    for lines whose subject_key matches any of the supplied identifiers.

    Expected line format (6 pipe-separated fields, whitespace trimmed):
        timestamp | system_id | resource_id | record_type | status | subject_key

    The subject_key may be an email address or a user_id (e.g. user_01).
    Matching is case-insensitive against the identifiers set.

    PII is redacted in raw_value: the subject_key field is replaced with
    '[PII_REDACTED]' in the stored line excerpt.
    """

    def __init__(self, gap_tracker, cache=None) -> None:
        self._gap = gap_tracker
        self._cache = cache   # not used for text files; kept for API symmetry

    def read(
        self,
        ref: EvidenceRef,
        file_path: Path,
        identifiers: Set[str],
    ) -> List[EvidenceFact]:
        """
        Parse *file_path* and return facts for lines matching *identifiers*.

        Parameters
        ----------
        ref:         EvidenceRef manifest row.
        file_path:   Absolute path to the .txt handover file.
        identifiers: Subject identifier set.

        Returns
        -------
        List of EvidenceFact in file order (deterministic).
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
                reason="txt_unreadable",
                detail=str(exc),
            )
            return []

        for lineno, raw_line in enumerate(lines, start=1):
            # ----------------------------------------------------------------
            # Skip header lines (no '|') and lines with fewer than 6 fields
            # ----------------------------------------------------------------
            if "|" not in raw_line:
                continue

            parts = [p.strip() for p in raw_line.split("|")]
            if len(parts) < 6:
                continue

            # ----------------------------------------------------------------
            # Unpack fields (take only the first 6; extras are silently ignored)
            # ----------------------------------------------------------------
            ts_raw, system_id, resource_id, record_type, status, subject_key = parts[:6]

            # ----------------------------------------------------------------
            # Filter: only process lines whose subject_key matches an identifier
            # ----------------------------------------------------------------
            if subject_key.lower() not in identifiers_lower:
                continue

            # ----------------------------------------------------------------
            # Parse captured_at
            # ----------------------------------------------------------------
            captured_at = ref.captured_at  # fallback
            if ts_raw:
                try:
                    captured_at = _parse_utc(ts_raw)
                except ValueError:
                    pass

            # ----------------------------------------------------------------
            # Infer RecordState from status
            # ----------------------------------------------------------------
            state = _STATUS_STATE_MAP.get(status.lower())
            if state is None:
                # Unknown status — still useful; default to PRESENT with review flag
                state = RecordState.PRESENT
                needs_review = True
            else:
                needs_review = False

            # ----------------------------------------------------------------
            # Build redacted raw_value
            # ----------------------------------------------------------------
            redacted_line = raw_line.replace(subject_key, "[PII_REDACTED]")

            # ----------------------------------------------------------------
            # Resolve subject identifier types
            # ----------------------------------------------------------------
            subject_key_lower = subject_key.lower()
            subject_email: Optional[str] = subject_key_lower if "@" in subject_key_lower else None
            subject_user_id: Optional[str] = (
                subject_key_lower if re.match(r"^user_\d+$", subject_key_lower) else None
            )

            # ----------------------------------------------------------------
            # Infer data_category from record_type if possible
            # ----------------------------------------------------------------
            data_category = _infer_category_from_record_type(record_type)

            fact = EvidenceFact(
                file_id=ref.file_id,
                file_path=ref.file_path,
                captured_at=captured_at,
                system_id=system_id or ref.origin or "unknown_service",
                resource_id=resource_id or ref.file_id,
                subject_user_id=subject_user_id,
                subject_email=subject_email,
                data_category=data_category,
                observed_state=state,
                raw_value=redacted_line[:500],
                source_span=f"line:{lineno}",
                llm_derived=False,
                needs_review=needs_review,
            )
            facts.append(fact)

        logger.debug(
            "TXTReader[%s]: %d matching facts from %d lines",
            ref.file_id,
            len(facts),
            len(lines),
        )
        return facts


# ---------------------------------------------------------------------------
# Helper: infer DataCategory from record_type string
# ---------------------------------------------------------------------------

_RECORD_TYPE_CATEGORY_MAP = [
    ({"user_profile", "profile", "account"},               DataCategory.USER_PROFILE),
    ({"search_index", "search"},                           DataCategory.SEARCH_INDEX_ENTRY),
    ({"analytics", "analytics_profile"},                   DataCategory.ANALYTICS_PROFILE),
    ({"support_message", "support", "ticket"},             DataCategory.SUPPORT_MESSAGE),
    ({"support_attachment", "attachment"},                  DataCategory.SUPPORT_ATTACHMENT),
    ({"export", "user_export"},                            DataCategory.USER_EXPORT),
    ({"marketing", "marketing_profile"},                   DataCategory.MARKETING_PROFILE),
    ({"email_delivery", "notification", "delivery_log"},   DataCategory.EMAIL_DELIVERY_LOG),
    ({"security_audit", "audit_log", "security"},          DataCategory.SECURITY_AUDIT_LOG),
    ({"legal_hold", "legal", "retention"},                 DataCategory.LEGAL_HOLD_RECORD),
    ({"backup", "archive"},                                DataCategory.BACKUP_ARCHIVE),
    ({"account_tombstone", "tombstone"},                   DataCategory.ACCOUNT_TOMBSTONE),
    ({"secondary_identifier", "identifier"},               DataCategory.SECONDARY_IDENTIFIER),
    ({"cache", "cache_entry"},                             DataCategory.CACHE_ENTRY),
    ({"telemetry", "product_telemetry"},                   DataCategory.PRODUCT_TELEMETRY),
]


def _infer_category_from_record_type(record_type: str) -> Optional[DataCategory]:
    """Return a DataCategory for *record_type*, or None if not recognizable."""
    rt_lower = record_type.lower().strip()
    for keywords, category in _RECORD_TYPE_CATEGORY_MAP:
        if rt_lower in keywords or any(kw in rt_lower for kw in keywords):
            return category
    return None
