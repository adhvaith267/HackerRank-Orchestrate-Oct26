"""
pipeline.py — EvidenceIngestionPipeline: the single entry-point for all evidence parsing.

Public API:
    EvidenceIngestionPipeline(manifest_index, dataset_root, cache_dir=None)
    .read_file(ref: EvidenceRef, identifiers: Set[str]) -> List[EvidenceFact]
    .read_all(refs: List[EvidenceRef], identifiers: Set[str]) -> List[EvidenceFact]
    .read_for_audit(refs: List[EvidenceRef], identifiers: Set[str],
                    audit_at: datetime) -> List[EvidenceFact]

Security contract:
    - All file paths are validated against dataset_root before reading.
    - SQL dumps are security-filtered via sql_reader._filter_sql before execution.
    - SQLite connections use :memory: with extension loading disabled.
    - Images are read from the pre-catalogued lookup table (no raw PII passed to LLM).
    - PDFs are extracted via pdftotext subprocess; OCR fallback recorded as a gap.
    - PII is redacted from all raw_value fields.
    - Event time (captured_at from manifest) is preserved separately from
      ingestion/extraction time.

Gap and error handling:
    - Missing files → gap recorded, empty list returned.
    - Malformed records → warning recorded, remaining records still processed.
    - Unsupported formats → warning recorded, empty list returned.
    - Fatal SQL security violations → EvidenceIngestionError raised (stops the run).

Determinism:
    - Facts are returned in file order (line/record index order within each file).
    - No random or time-dependent behaviour.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Type

from ghost_audit.schemas import EvidenceFact, EvidenceFormat, EvidenceRef
from ghost_audit.evidence_ingestion.gap_tracker import EvidenceIngestionError, GapTracker
from ghost_audit.evidence_ingestion.cache import ExtractionCache
from ghost_audit.evidence_ingestion.manifest import ManifestIndex
from ghost_audit.evidence_ingestion.sql_reader import SQLReader
from ghost_audit.evidence_ingestion.json_reader import JSONReader
from ghost_audit.evidence_ingestion.log_reader import LogReader
from ghost_audit.evidence_ingestion.pdf_reader import PDFReader
from ghost_audit.evidence_ingestion.image_reader import ImageReader
from ghost_audit.evidence_ingestion.txt_reader import TXTReader

logger = logging.getLogger(__name__)


class EvidenceIngestionPipeline:
    """
    Unified evidence ingestion pipeline.

    Dispatches each EvidenceRef to the appropriate format reader,
    collects EvidenceFacts, and records gaps/warnings.

    Parameters
    ----------
    manifest_index:
        Pre-built ManifestIndex providing EvidenceRef objects and path validation.
    dataset_root:
        Absolute path to the dataset/ directory.  All evidence paths are
        resolved relative to this root.
    cache_dir:
        Optional directory for the ExtractionCache (PDF/SQL results).
        Defaults to ``<dataset_root>/../.evidence_cache``.
    gap_tracker:
        Optional shared GapTracker.  A new instance is created if None.
    """

    # Extractor version string — bump whenever extraction logic changes.
    EXTRACTOR_VERSION = "1.0.0"

    def __init__(
        self,
        manifest_index: ManifestIndex,
        dataset_root: Path,
        cache_dir: Optional[Path] = None,
        gap_tracker: Optional[GapTracker] = None,
    ) -> None:
        self._manifest = manifest_index
        self._dataset_root = Path(dataset_root).resolve()
        self._gap = gap_tracker or GapTracker()

        # Build the shared extraction cache
        if cache_dir is None:
            cache_dir = self._dataset_root.parent / ".evidence_cache"
        self._cache = ExtractionCache(
            cache_dir=cache_dir,
            extractor_name="evidence_pipeline",
            extractor_version=self.EXTRACTOR_VERSION,
        )

        # Instantiate all format readers (share the same gap_tracker + cache)
        self._sql_reader = SQLReader(self._gap, self._cache)
        self._json_reader = JSONReader(self._gap, self._cache)
        self._log_reader = LogReader(self._gap, self._cache)
        self._pdf_reader = PDFReader(self._gap, self._cache)
        self._image_reader = ImageReader(self._gap, self._cache)
        self._txt_reader = TXTReader(self._gap, self._cache)

        # Format dispatch table
        self._readers = {
            EvidenceFormat.SQL:   self._sql_reader,
            EvidenceFormat.JSON:  self._json_reader,
            EvidenceFormat.LOG:   self._log_reader,
            EvidenceFormat.PDF:   self._pdf_reader,
            EvidenceFormat.IMAGE: self._image_reader,
            EvidenceFormat.TXT:   self._txt_reader,
        }

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def gap_tracker(self) -> GapTracker:
        """Expose the internal GapTracker for inspection after a run."""
        return self._gap

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def read_file(
        self,
        ref: EvidenceRef,
        identifiers: Set[str],
    ) -> List[EvidenceFact]:
        """
        Parse a single evidence file and return matching facts.

        Parameters
        ----------
        ref:
            EvidenceRef from the manifest.
        identifiers:
            Set of subject identifiers (emails, user_ids, hashes).

        Returns
        -------
        List[EvidenceFact]
            Empty list on read errors or when no records match.

        Raises
        ------
        EvidenceIngestionError
            When a fatal SQL security violation is detected.
        """
        # Resolve the absolute path within dataset_root
        try:
            self._manifest.validate_path(ref.file_path)
        except ValueError as exc:
            self._gap.warn(ref.file_id, f"path_traversal_blocked: {exc}")
            return []

        # The manifest stores paths relative to dataset/
        # (e.g. "evidence/logs/foo.log"), so we join them onto dataset_root
        abs_path = (self._dataset_root / ref.file_path).resolve()

        if not abs_path.exists():
            self._gap.gap(ref.file_id, "file_not_found_on_disk")
            return []

        reader = self._readers.get(ref.format)
        if reader is None:
            self._gap.warn(
                ref.file_id,
                f"unsupported_format: {ref.format!r}",
            )
            return []

        try:
            facts = reader.read(ref, abs_path, identifiers)
        except EvidenceIngestionError:
            raise  # propagate fatal security violations
        except Exception as exc:
            logger.error(
                "Unexpected error reading %s (%s): %s",
                ref.file_id,
                ref.format,
                exc,
                exc_info=True,
            )
            self._gap.warn(
                ref.file_id,
                f"unexpected_reader_error: {type(exc).__name__}",
            )
            return []

        if not facts:
            self._gap.gap(ref.file_id, "no_matching_facts")

        logger.debug(
            "Pipeline[%s] format=%s facts=%d",
            ref.file_id,
            ref.format,
            len(facts),
        )
        return facts

    def read_all(
        self,
        refs: List[EvidenceRef],
        identifiers: Set[str],
    ) -> List[EvidenceFact]:
        """
        Parse multiple evidence files and aggregate their facts.

        Processing order matches the order of *refs*.  Each file's facts
        are appended in their internal (deterministic) order.

        Parameters
        ----------
        refs:
            List of EvidenceRef objects to process.
        identifiers:
            Subject identifier set.

        Returns
        -------
        List[EvidenceFact]
            Aggregated facts in processing order.
        """
        all_facts: List[EvidenceFact] = []
        for ref in refs:
            all_facts.extend(self.read_file(ref, identifiers))
        return all_facts

    def read_for_audit(
        self,
        refs: List[EvidenceRef],
        identifiers: Set[str],
        audit_at: datetime,
    ) -> List[EvidenceFact]:
        """
        Parse evidence files, excluding those captured after *audit_at*.

        This is the primary method for audit-case processing: it enforces
        the temporal boundary so that evidence from after the audit cutoff
        is never used for a case decision.

        Parameters
        ----------
        refs:
            All candidate EvidenceRef objects.
        identifiers:
            Subject identifier set.
        audit_at:
            Audit cutoff timestamp (UTC-aware).  Files with
            ``captured_at > audit_at`` are skipped.

        Returns
        -------
        List[EvidenceFact]
            Facts from eligible files only, in processing order.
        """
        if audit_at.tzinfo is None:
            audit_at = audit_at.replace(tzinfo=timezone.utc)

        eligible = [r for r in refs if r.captured_at <= audit_at]
        skipped = len(refs) - len(eligible)
        if skipped:
            logger.debug(
                "read_for_audit: skipped %d post-audit_at file(s)", skipped
            )

        return self.read_all(eligible, identifiers)

    def ingest_from_manifest(
        self,
        identifiers: Set[str],
        audit_at: Optional[datetime] = None,
    ) -> List[EvidenceFact]:
        """
        Convenience method: ingest all files in the manifest index.

        If *audit_at* is supplied, files captured after that timestamp
        are excluded.  Otherwise all files are processed.

        Parameters
        ----------
        identifiers:
            Subject identifier set.
        audit_at:
            Optional temporal boundary.

        Returns
        -------
        List[EvidenceFact]
        """
        all_refs = self._manifest.all_refs()
        if audit_at is not None:
            return self.read_for_audit(all_refs, identifiers, audit_at)
        return self.read_all(all_refs, identifiers)
