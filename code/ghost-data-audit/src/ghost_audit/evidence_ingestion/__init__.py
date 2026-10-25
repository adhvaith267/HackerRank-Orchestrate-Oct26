"""
evidence_ingestion — sub-package for reading and extracting facts from evidence files.

Public API:
    GapTracker               — thread-safe warning + coverage-gap registry
    EvidenceIngestionError   — raised by GapTracker.fatal()
    ExtractionCache          — SHA-256-keyed disk cache for extractor results
    ManifestIndex            — loads evidence_files.csv, validates paths, detects gaps
    EvidenceIngestionPipeline — dispatches each EvidenceRef to the correct reader
    SQLReader                — safe SQL dump reader (allow-list filter + :memory: SQLite)
    JSONReader               — JSON/JSONL evidence reader (6 variant dispatcher)
    LogReader                — structured key=value service-log reader
    PDFReader                — PDF text extraction via pdftotext (+ OCR gap recording)
    ImageReader              — catalogue-backed image fact reader
    TXTReader                — pipe-delimited shift handover document reader

All readers share a uniform interface::

    reader.read(ref: EvidenceRef, file_path: Path, identifiers: Set[str])
        -> List[EvidenceFact]

Usage example::

    from pathlib import Path
    from ghost_audit.evidence_ingestion import (
        GapTracker, ManifestIndex, EvidenceIngestionPipeline
    )

    gap = GapTracker()
    manifest = ManifestIndex(
        evidence_files_path=Path("dataset/evidence_files.csv"),
        evidence_root=Path("dataset/evidence"),
    )
    pipeline = EvidenceIngestionPipeline(
        manifest_index=manifest,
        dataset_root=Path("dataset"),
        gap_tracker=gap,
    )
    facts = pipeline.read_for_audit(
        refs=manifest.all_refs(),
        identifiers={"user_01", "alice@example.com"},
        audit_at=audit_at_datetime,
    )
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Core infrastructure — import order matters: gap_tracker and cache have
# no internal dependencies; readers depend on gap_tracker.
# ---------------------------------------------------------------------------

from ghost_audit.evidence_ingestion.gap_tracker import (
    CoverageGap,
    EvidenceIngestionError,
    ExtractionWarning,
    GapTracker,
)

from ghost_audit.evidence_ingestion.cache import ExtractionCache

from ghost_audit.evidence_ingestion.manifest import ManifestIndex

# ---------------------------------------------------------------------------
# Format readers
# ---------------------------------------------------------------------------

from ghost_audit.evidence_ingestion.sql_reader import SQLReader
from ghost_audit.evidence_ingestion.json_reader import JSONReader
from ghost_audit.evidence_ingestion.log_reader import LogReader
from ghost_audit.evidence_ingestion.pdf_reader import PDFReader
from ghost_audit.evidence_ingestion.image_reader import ImageReader
from ghost_audit.evidence_ingestion.txt_reader import TXTReader

# ---------------------------------------------------------------------------
# High-level pipeline
# ---------------------------------------------------------------------------

from ghost_audit.evidence_ingestion.pipeline import EvidenceIngestionPipeline

# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    # Core infrastructure
    "GapTracker",
    "EvidenceIngestionError",
    "ExtractionWarning",
    "CoverageGap",
    "ExtractionCache",
    "ManifestIndex",
    # Format readers
    "SQLReader",
    "JSONReader",
    "LogReader",
    "PDFReader",
    "ImageReader",
    "TXTReader",
    # High-level pipeline
    "EvidenceIngestionPipeline",
]
