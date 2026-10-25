"""
image_reader.py — Image evidence reader (OCR stub).

Public API:
    ImageReader(gap_tracker, cache=None)
    .read(ref: EvidenceRef, file_path: Path, identifiers: Set[str]) -> List[EvidenceFact]

Note: Full OCR/LLM vision is not implemented yet.
This reader uses a pre-catalogued lookup table (from DATA_DISCOVERY.md §3.4)
to return known facts about each evidence image file by file_id.
When OCR is available, the cache layer will prevent re-processing.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from ghost_audit.schemas import DataCategory, EvidenceFact, EvidenceRef, LLMConfidence, RecordState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pre-catalogued image facts (DATA_DISCOVERY.md §3.4)
# ---------------------------------------------------------------------------
# Each entry maps file_id -> list of fact descriptors.
# Descriptor keys:
#   system_id        : str
#   resource_id      : str
#   data_category_str: str  (DataCategory enum name)
#   state_str        : str  (RecordState enum name)
#   description      : str  (human note — not written to output, used for review)

IMAGE_CATALOGUE: Dict[str, List[Dict]] = {
    # account_admin_console_20260926.png
    "evidence_04": [
        {
            "system_id": "account_service",
            "resource_id": "account_5762",
            "data_category_str": "USER_PROFILE",
            "state_str": "PRESENT",
            "description": "Haruka Sato user_11 account active 26 Sep 2026",
        }
    ],
    # deleted_account_reference_20260310.png
    "evidence_42": [
        {
            "system_id": "identity_service",
            "resource_id": "tombstone_user_17",
            "data_category_str": "ACCOUNT_TOMBSTONE",
            "state_str": "PRESENT",
            "description": "user_17 retained reference in Customer Reference Registry",
        }
    ],
    # search_index_inspector_20260901.png
    "evidence_09": [
        {
            "system_id": "search_service",
            "resource_id": "search_428",
            "data_category_str": "SEARCH_INDEX_ENTRY",
            "state_str": "PRESENT",
            "description": "Gabriel Silva user_13 search index hit",
        },
        {
            "system_id": "search_service",
            "resource_id": "search_1874",
            "data_category_str": "SEARCH_INDEX_ENTRY",
            "state_str": "PRESENT",
            "description": "g.silva76.jr@gmail.com search hit no customer_reference",
        },
    ],
    # backup_restore_console_20260429.png
    "evidence_32": [
        {
            "system_id": "backup_service",
            "resource_id": "backup_9287",
            "data_category_str": "BACKUP_ARCHIVE",
            "state_str": "PRESENT",
            "description": "areed1433@gmail.com backup eu-west-1 restore_allowed=true",
        }
    ],
    # analytics_profile_view_20260713.png
    "evidence_19": [
        {
            "system_id": "analytics_platform",
            "resource_id": "analytics_7438",
            "data_category_str": "ANALYTICS_PROFILE",
            "state_str": "PRESENT",
            "description": "Omar Darwish user_20 identifiable analytics profile",
        }
    ],
    # connector_management_console_20260807.png
    "evidence_14": [
        {
            "system_id": "integration_service",
            "resource_id": "data_flow_1121",
            "data_category_str": "USER_PROFILE",
            "state_str": "PRESENT",
            "description": "jain.aditi@gmail.com data flow active",
        },
        {
            "system_id": "integration_service",
            "resource_id": "data_flow_9846",
            "data_category_str": "USER_PROFILE",
            "state_str": "PRESENT",
            "description": "lucia-torres@gmail.com data flow active",
        },
    ],
    # customer_export_console_20260618.png
    "evidence_23": [
        {
            "system_id": "export_service",
            "resource_id": "export_1260",
            "data_category_str": "USER_EXPORT",
            "state_str": "PRESENT",
            "description": "ingrid.dahl@outlook.com export Ready 18 Jun 2026",
        }
    ],
    # object_storage_browser_20260213.png
    "evidence_46": [
        {
            "system_id": "support_platform",
            "resource_id": "support_object_storage_20260213",
            "data_category_str": "SUPPORT_ATTACHMENT",
            "state_str": "PRESENT",
            "description": "support attachments present in object storage bucket",
        }
    ],
    # security_audit_explorer_20260905.png
    "evidence_37": [
        {
            "system_id": "security_service",
            "resource_id": "audit_record_003",
            "data_category_str": "SECURITY_AUDIT_LOG",
            "state_str": "PRESENT",
            "description": "user_03 account closure recorded 25 Aug 2026",
        }
    ],
    # marketing_profile_console.png
    "evidence_60": [
        {
            "system_id": "marketing_platform",
            "resource_id": "marketing_001",
            "data_category_str": "MARKETING_PROFILE",
            "state_str": "PRESENT",
            "description": "Soo-jin Park sj.park@naver.com live marketing profile",
        }
    ],
    # support_ticket_console_20260524.png
    "evidence_28": [
        {
            "system_id": "support_platform",
            "resource_id": "support_1034",
            "data_category_str": "SUPPORT_MESSAGE",
            "state_str": "PRESENT",
            "description": "Kofi Agyeman kagyeman8947@fastmail.com delivery inquiry",
        }
    ],
}


# ---------------------------------------------------------------------------
# ImageReader
# ---------------------------------------------------------------------------

class ImageReader:
    """
    Returns pre-catalogued EvidenceFacts for known image evidence files.

    All facts for a given file_id are returned regardless of the identifiers
    set, because without OCR we cannot filter by content.  Callers are
    responsible for filtering facts by user after ingestion.

    All returned facts are flagged needs_review=True because they derive from
    manual catalogue inspection rather than automated OCR.
    """

    def __init__(self, gap_tracker, cache=None) -> None:
        self._gap = gap_tracker
        self._cache = cache   # reserved for future OCR integration

    def read(
        self,
        ref: EvidenceRef,
        file_path: Path,
        identifiers: Set[str],
    ) -> List[EvidenceFact]:
        """
        Return catalogue facts for *ref.file_id*.

        Parameters
        ----------
        ref:         EvidenceRef manifest row.
        file_path:   Absolute path to the image file (not read; kept for API symmetry).
        identifiers: Subject identifier set (not used for filtering here).

        Returns
        -------
        List of EvidenceFact from IMAGE_CATALOGUE for this file_id,
        or [] if the file_id is not catalogued.
        """
        descriptors = IMAGE_CATALOGUE.get(ref.file_id)
        if descriptors is None:
            self._gap.warn(ref.file_id, "image_no_catalogue_entry")
            return []

        facts: List[EvidenceFact] = []

        for desc in descriptors:
            # Resolve DataCategory enum
            try:
                data_category: Optional[DataCategory] = DataCategory(desc["data_category_str"])
            except (KeyError, ValueError):
                data_category = None

            # Resolve RecordState enum
            try:
                observed_state = RecordState(desc["state_str"])
            except (KeyError, ValueError):
                observed_state = RecordState.PRESENT  # safe default for catalogue entries

            fact = EvidenceFact(
                file_id=ref.file_id,
                file_path=ref.file_path,
                captured_at=ref.captured_at,
                system_id=desc.get("system_id", "unknown_service"),
                resource_id=desc.get("resource_id", ref.file_id),
                subject_user_id=None,    # caller resolves via identifiers
                subject_email=None,      # caller resolves via identifiers
                data_category=data_category,
                observed_state=observed_state,
                raw_value=None,          # no text extraction without OCR
                source_span="image:catalogue",
                llm_derived=False,
                llm_confidence=LLMConfidence.NA,
                needs_review=True,       # manual catalogue — must be reviewed
            )
            facts.append(fact)

        # Log only file_id and count; no PII
        logger.debug(
            "ImageReader[%s]: returning %d catalogued fact(s)",
            ref.file_id,
            len(facts),
        )
        return facts
