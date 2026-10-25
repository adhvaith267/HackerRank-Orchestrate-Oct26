"""
manifest.py — Manifest index for evidence_files.csv.

Public API:
    ManifestIndex(evidence_files_path, evidence_root)
    .get(file_id) -> Optional[EvidenceRef]
    .all_refs() -> List[EvidenceRef]
    .validate_path(file_path) -> None   # raises ValueError on traversal
    .gaps -> List[str]   # files in manifest that don't exist on disk
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, List, Optional

from ghost_audit.schemas import EvidenceFormat, EvidenceRef

logger = logging.getLogger(__name__)

# Mapping from lowercase file extension to EvidenceFormat
_EXT_TO_FORMAT: Dict[str, EvidenceFormat] = {
    "sql": EvidenceFormat.SQL,
    "json": EvidenceFormat.JSON,
    "log": EvidenceFormat.LOG,
    "pdf": EvidenceFormat.PDF,
    "png": EvidenceFormat.IMAGE,
    "jpg": EvidenceFormat.IMAGE,
    "jpeg": EvidenceFormat.IMAGE,
    "txt": EvidenceFormat.TXT,
}


def _infer_format(file_path: str) -> EvidenceFormat:
    """Infer EvidenceFormat from a file extension. Raises ValueError if unknown."""
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    fmt = _EXT_TO_FORMAT.get(ext)
    if fmt is None:
        raise ValueError(
            f"Cannot infer EvidenceFormat from extension {ext!r} "
            f"in path {Path(file_path).name!r}"
        )
    return fmt


class ManifestIndex:
    """
    Builds and exposes a file-id-keyed index of EvidenceRef objects
    loaded from evidence_files.csv.

    Path traversal is prevented at two levels:
      1. Any path containing a '..' component is rejected before resolution.
      2. After resolution, the canonical path must start with evidence_root.resolve().
    """

    def __init__(self, evidence_files_path: Path, evidence_root: Path) -> None:
        """
        Parameters
        ----------
        evidence_files_path:
            Path to evidence_files.csv.
        evidence_root:
            Absolute base directory for all evidence files (e.g. dataset/evidence/).
        """
        self._evidence_root: Path = evidence_root.resolve()
        self._index: Dict[str, EvidenceRef] = {}
        self._gaps: List[str] = []

        self._load(evidence_files_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, file_id: str) -> Optional[EvidenceRef]:
        """Return the EvidenceRef for *file_id*, or None if not found."""
        return self._index.get(file_id)

    def all_refs(self) -> List[EvidenceRef]:
        """Return all EvidenceRef objects in insertion order."""
        return list(self._index.values())

    def validate_path(self, file_path: str) -> None:
        """
        Raise ValueError if *file_path* would escape evidence_root.

        Checks performed (in order):
          1. The path must not contain any '..' component.
          2. After joining with evidence_root and resolving, the result
             must be under evidence_root.
        """
        # Check 1: reject '..' components before any filesystem operation
        p = Path(file_path)
        if any(part == ".." for part in p.parts):
            raise ValueError(
                f"Path traversal detected: '..' component in {p.name!r}"
            )

        # Check 2: canonical path containment check
        resolved = (self._evidence_root / file_path).resolve()
        try:
            resolved.relative_to(self._evidence_root)
        except ValueError:
            raise ValueError(
                f"Path traversal detected: resolved path escapes evidence root "
                f"(file name: {p.name!r})"
            )

    @property
    def gaps(self) -> List[str]:
        """
        List of file_ids whose resolved paths do not exist on disk.
        Populated at construction time.
        """
        return list(self._gaps)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load(self, csv_path: Path) -> None:
        """Parse evidence_files.csv and populate _index and _gaps."""
        required_columns = {"file_id", "file_path", "origin", "captured_at"}

        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)

            if reader.fieldnames is None:
                logger.warning("evidence_files.csv appears to be empty")
                return

            actual_columns = set(reader.fieldnames)
            missing = required_columns - actual_columns
            if missing:
                raise ValueError(
                    f"evidence_files.csv is missing required columns: {missing}"
                )

            for row_num, row in enumerate(reader, start=2):  # row 1 = header
                file_id = row["file_id"].strip()
                file_path = row["file_path"].strip()
                origin = row["origin"].strip()
                captured_at_raw = row["captured_at"].strip()

                if not file_id:
                    logger.warning(
                        "Row %d in evidence_files.csv has an empty file_id; skipping",
                        row_num,
                    )
                    continue

                # Duplicate file_id: keep first, warn and skip
                if file_id in self._index:
                    logger.warning(
                        "[%s] Duplicate file_id in evidence_files.csv at row %d; "
                        "keeping first entry",
                        file_id,
                        row_num,
                    )
                    continue

                # Anti-traversal validation
                try:
                    self.validate_path(file_path)
                except ValueError as exc:
                    logger.warning(
                        "[%s] %s — skipping entry", file_id, exc
                    )
                    continue

                # Resolve absolute path (for existence check)
                resolved = (self._evidence_root / file_path).resolve()

                # Infer format from extension
                try:
                    fmt = _infer_format(file_path)
                except ValueError as exc:
                    logger.warning("[%s] %s — skipping entry", file_id, exc)
                    continue

                # Build EvidenceRef (pydantic validates captured_at via _parse_ts)
                try:
                    ref = EvidenceRef(
                        file_id=file_id,
                        file_path=file_path,
                        origin=origin,
                        captured_at_raw=captured_at_raw,
                        captured_at=captured_at_raw,  # validator parses the string
                        format=fmt,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "[%s] Failed to build EvidenceRef: %s — skipping",
                        file_id,
                        exc,
                    )
                    continue

                self._index[file_id] = ref

                # Check disk existence; collect gaps using relative path only
                if not resolved.exists():
                    rel = Path(file_path)
                    logger.warning(
                        "[%s] Evidence file not found on disk: %s",
                        file_id,
                        rel,
                    )
                    self._gaps.append(file_id)

        logger.info(
            "ManifestIndex loaded: %d entries, %d gap(s)",
            len(self._index),
            len(self._gaps),
        )
