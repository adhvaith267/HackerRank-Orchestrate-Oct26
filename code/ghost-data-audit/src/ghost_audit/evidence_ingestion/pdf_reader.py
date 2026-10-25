"""
pdf_reader.py — PDF text extraction.

Public API:
    PDFReader(gap_tracker, cache=None)
    .read(ref: EvidenceRef, file_path: Path, identifiers: Set[str]) -> List[EvidenceFact]

Extraction strategy:
    1. Try pdftotext (poppler) via subprocess
    2. If unavailable or fails, record extraction failure in gap_tracker
    3. Cache the extracted text by SHA-256 + extractor version
    4. Search the extracted text for identifiers
    5. Build one EvidenceFact per PDF page that contains an identifier match
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Set

from ghost_audit.schemas import DataCategory, EvidenceFact, EvidenceRef, RecordState, _parse_utc

logger = logging.getLogger(__name__)

# Bump this string whenever the extraction logic changes to invalidate cached text.
EXTRACTOR_VERSION = "1.0"

# Form-feed separates PDF pages in pdftotext output
_PAGE_SEP = "\f"

# ---------------------------------------------------------------------------
# Resource-ID patterns
# ---------------------------------------------------------------------------

_RESOURCE_ID_RE = re.compile(
    r"\b(support_\d+|export_\d+|account_\d+|audit_record_\d+|legal_hold_\d+)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Data-category inference from filename keywords
# ---------------------------------------------------------------------------

_CATEGORY_KEYWORD_MAP = [
    ({"support", "delivery", "ticket", "attachment"}, DataCategory.SUPPORT_ATTACHMENT),
    ({"legal", "retention", "hold"},                  DataCategory.LEGAL_HOLD_RECORD),
    ({"security", "compliance", "audit"},              DataCategory.SECURITY_AUDIT_LOG),
    ({"account", "statement", "profile", "invoice"},   DataCategory.USER_PROFILE),
    ({"export"},                                       DataCategory.USER_EXPORT),
    ({"marketing"},                                    DataCategory.MARKETING_PROFILE),
    ({"analytics"},                                    DataCategory.ANALYTICS_PROFILE),
    ({"backup", "archive"},                            DataCategory.BACKUP_ARCHIVE),
]


def _infer_data_category(filename: str) -> DataCategory:
    """Return the most-specific DataCategory matching *filename* keywords."""
    name_lower = filename.lower()
    for keywords, category in _CATEGORY_KEYWORD_MAP:
        if any(kw in name_lower for kw in keywords):
            return category
    return DataCategory.USER_PROFILE  # fallback


def _infer_system_id(origin: str) -> str:
    """
    Map an EvidenceRef.origin string to a canonical system_id.
    Falls back to a sanitised version of origin if no known mapping matches.
    """
    origin_lower = (origin or "").lower()
    _ORIGIN_MAP = {
        "support_platform":   "support_platform",
        "support":            "support_platform",
        "legal_service":      "legal_service",
        "legal":              "legal_service",
        "security_service":   "security_service",
        "security":           "security_service",
        "account_service":    "account_service",
        "account":            "account_service",
        "export_service":     "export_service",
        "export":             "export_service",
        "analytics_platform": "analytics_platform",
        "analytics":          "analytics_platform",
        "marketing_platform": "marketing_platform",
        "marketing":          "marketing_platform",
        "backup_service":     "backup_service",
        "backup":             "backup_service",
        "identity_service":   "identity_service",
        "identity":           "identity_service",
    }
    for key, val in _ORIGIN_MAP.items():
        if key in origin_lower:
            return val
    # Sanitize origin as fallback
    return re.sub(r"[^\w_]", "_", origin_lower).strip("_") or "unknown_service"


# ---------------------------------------------------------------------------
# PII redaction helper (shared pattern)
# ---------------------------------------------------------------------------

def _redact_text(text: str, identifiers_lower: Set[str]) -> str:
    """Replace every identifier occurrence in *text* with '[PII_REDACTED]'."""
    result = text
    for ident in identifiers_lower:
        if not ident:
            continue
        result = re.sub(re.escape(ident), "[PII_REDACTED]", result, flags=re.IGNORECASE)
    return result


# ---------------------------------------------------------------------------
# PDFReader
# ---------------------------------------------------------------------------

class PDFReader:
    """
    Extracts text from PDF evidence files using pdftotext (poppler).

    Extracted text is cached by file SHA-256 + EXTRACTOR_VERSION to avoid
    redundant subprocess calls.  Facts (which depend on per-user identifiers)
    are NOT cached.
    """

    def __init__(self, gap_tracker, cache=None) -> None:
        self._gap = gap_tracker
        self._cache = cache   # ExtractionCache | None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_text(self, file_path: Path) -> Optional[str]:
        """
        Run pdftotext on *file_path* and return the full extracted text,
        or None on failure.  Uses self._cache when available.
        """
        # Try cache first
        if self._cache is not None:
            if hasattr(self._cache, "get_text"):
                cached = self._cache.get_text(file_path, EXTRACTOR_VERSION)
            else:
                # Compatibility with the small in-memory cache used by tests.
                cached = self._cache.get(file_path, EXTRACTOR_VERSION)
            if cached is not None:
                logger.debug("PDFReader: cache hit for %s", file_path.name)
                return cached

        try:
            result = subprocess.run(
                ["pdftotext", "-layout", str(file_path), "-"],
                capture_output=True,
                timeout=30,
            )
        except FileNotFoundError:
            # pdftotext binary not found
            return None
        except subprocess.TimeoutExpired:
            raise RuntimeError("pdftotext timed out")

        if result.returncode != 0:
            raise RuntimeError(
                f"pdftotext exited {result.returncode}: "
                f"{result.stderr.decode('utf-8', errors='replace')[:200]}"
            )

        text = result.stdout.decode("utf-8", errors="replace")

        # Store in cache (raw text, not facts)
        if self._cache is not None:
            if hasattr(self._cache, "put_text"):
                self._cache.put_text(file_path, EXTRACTOR_VERSION, text)
            else:
                self._cache.put(file_path, EXTRACTOR_VERSION, text)

        return text

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def read(
        self,
        ref: EvidenceRef,
        file_path: Path,
        identifiers: Set[str],
    ) -> List[EvidenceFact]:
        """
        Extract facts from a PDF file.

        One EvidenceFact is produced per page that contains at least one
        of the caller-supplied identifiers.

        Parameters
        ----------
        ref:         EvidenceRef manifest row.
        file_path:   Absolute path to the PDF file.
        identifiers: Subject identifier set (emails, user_ids, hashes, etc.).

        Returns
        -------
        List of EvidenceFact in page order.
        """
        if not identifiers:
            return []

        identifiers_lower: Set[str] = {i.lower() for i in identifiers if i}

        # ----------------------------------------------------------------
        # Extract text
        # ----------------------------------------------------------------
        try:
            text = self._extract_text(file_path)
        except FileNotFoundError:
            # pdftotext not installed
            self._gap.warn(ref.file_id, "pdftotext_unavailable")
            return []
        except Exception as exc:
            self._gap.warn(ref.file_id, "pdf_extraction_failed", detail=str(exc))
            return []

        if text is None:
            # FileNotFoundError path above handles this, but guard defensively
            self._gap.warn(ref.file_id, "pdftotext_unavailable")
            return []

        # ----------------------------------------------------------------
        # Split into pages by form-feed
        # ----------------------------------------------------------------
        pages = text.split(_PAGE_SEP)

        facts: List[EvidenceFact] = []

        system_id = _infer_system_id(ref.origin)
        data_category = _infer_data_category(Path(ref.file_path).name)

        for page_index, page_text in enumerate(pages, start=1):
            page_lower = page_text.lower()

            # Skip pages without any identifier
            if not any(ident in page_lower for ident in identifiers_lower):
                continue

            # ----------------------------------------------------------------
            # Extract resource_id from page text
            # ----------------------------------------------------------------
            rid_match = _RESOURCE_ID_RE.search(page_text)
            resource_id: str = rid_match.group(1).lower() if rid_match else ref.file_id

            # ----------------------------------------------------------------
            # Resolve subject identifiers
            # ----------------------------------------------------------------
            subject_email: Optional[str] = None
            subject_user_id: Optional[str] = None
            for ident in identifiers_lower:
                if "@" in ident and ident in page_lower:
                    subject_email = ident
                if re.match(r"^user_\d+$", ident) and ident in page_lower:
                    subject_user_id = ident

            # ----------------------------------------------------------------
            # Build redacted raw_value (first 200 chars of page)
            # ----------------------------------------------------------------
            raw_preview = _redact_text(page_text[:200], identifiers_lower)

            fact = EvidenceFact(
                file_id=ref.file_id,
                file_path=ref.file_path,
                captured_at=ref.captured_at,
                system_id=system_id,
                resource_id=resource_id,
                subject_user_id=subject_user_id,
                subject_email=subject_email,
                data_category=data_category,
                observed_state=RecordState.PRESENT,
                raw_value=raw_preview,
                source_span=f"pdf:page:{page_index}",
                llm_derived=False,
                needs_review=False,
            )
            facts.append(fact)

        logger.debug(
            "PDFReader[%s]: %d matching page(s) from %d page(s) total",
            ref.file_id,
            len(facts),
            len(pages),
        )
        return facts
