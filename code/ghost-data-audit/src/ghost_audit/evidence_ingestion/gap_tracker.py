"""
gap_tracker.py — Structured warning and coverage-gap registry.

Public API:
    GapTracker()
    .warn(file_id, reason, detail=None) -> None   # adds an ExtractionWarning
    .gap(file_id, reason) -> None                 # adds a CoverageGap
    .fatal(file_id, reason) -> None               # raises EvidenceIngestionError
    .warnings -> List[ExtractionWarning]
    .gaps -> List[CoverageGap]
    .summary() -> dict

Exceptions:
    EvidenceIngestionError(message, file_id)

Dataclasses:
    ExtractionWarning(file_id, reason, detail, timestamp)
    CoverageGap(file_id, reason, timestamp)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class EvidenceIngestionError(Exception):
    """
    Raised by GapTracker.fatal() when evidence ingestion encounters an
    unrecoverable error for a specific file.

    Attributes
    ----------
    file_id:
        The file_id associated with the error.
    """

    def __init__(self, message: str, file_id: str) -> None:
        super().__init__(message)
        self.file_id = file_id

    def __repr__(self) -> str:  # pragma: no cover
        return f"EvidenceIngestionError(file_id={self.file_id!r}, message={str(self)!r})"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    """Return the current UTC-aware datetime."""
    return datetime.now(tz=timezone.utc)


@dataclass(frozen=True)
class ExtractionWarning:
    """
    A non-fatal warning produced during evidence extraction.

    Fields
    ------
    file_id:
        The evidence file_id this warning is about.
    reason:
        Short machine-readable reason code or message (no PII).
    detail:
        Optional human-readable elaboration (no PII).
    timestamp:
        UTC time when the warning was created.
    """

    file_id: str
    reason: str
    detail: Optional[str]
    timestamp: datetime = field(default_factory=_utc_now)


@dataclass(frozen=True)
class CoverageGap:
    """
    A coverage gap: an evidence file that could not be processed or
    contributed no usable facts.

    Fields
    ------
    file_id:
        The evidence file_id that is missing or incomplete.
    reason:
        Short machine-readable reason code or message (no PII).
    timestamp:
        UTC time when the gap was recorded.
    """

    file_id: str
    reason: str
    timestamp: datetime = field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# GapTracker
# ---------------------------------------------------------------------------


class GapTracker:
    """
    Thread-safe registry of extraction warnings and coverage gaps.

    All appends are protected by a single ``threading.Lock``, so the
    registry is safe to use from multiple threads (e.g. a thread-pool
    extractor pipeline).

    Logs never include PII — only ``file_id`` and ``reason``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._warnings: List[ExtractionWarning] = []
        self._gaps: List[CoverageGap] = []

    # ------------------------------------------------------------------
    # Public API — mutators
    # ------------------------------------------------------------------

    def warn(
        self,
        file_id: str,
        reason: str,
        detail: Optional[str] = None,
    ) -> None:
        """
        Record a non-fatal extraction warning.

        Logs at WARNING level.  Neither *reason* nor *detail* must contain PII.

        Parameters
        ----------
        file_id:
            The evidence file_id this warning concerns.
        reason:
            Short, machine-readable description of the problem.
        detail:
            Optional additional context (no PII).
        """
        logger.warning("[%s] %s", file_id, reason)
        entry = ExtractionWarning(file_id=file_id, reason=reason, detail=detail)
        with self._lock:
            self._warnings.append(entry)

    def gap(self, file_id: str, reason: str) -> None:
        """
        Record a coverage gap: evidence that is absent or yielded no facts.

        Logs at WARNING level.  *reason* must not contain PII.

        Parameters
        ----------
        file_id:
            The evidence file_id with the gap.
        reason:
            Short, machine-readable description of why coverage is incomplete.
        """
        logger.warning("[%s] %s", file_id, reason)
        entry = CoverageGap(file_id=file_id, reason=reason)
        with self._lock:
            self._gaps.append(entry)

    def fatal(self, file_id: str, reason: str) -> None:
        """
        Log a fatal ingestion error and raise EvidenceIngestionError.

        Logs at ERROR level before raising.

        Parameters
        ----------
        file_id:
            The evidence file_id that triggered the fatal error.
        reason:
            Short, machine-readable description of the fatal condition.

        Raises
        ------
        EvidenceIngestionError
            Always raised after logging.
        """
        logger.error("[%s] %s", file_id, reason)
        raise EvidenceIngestionError(
            message=f"[{file_id}] {reason}",
            file_id=file_id,
        )

    # ------------------------------------------------------------------
    # Public API — read-only properties
    # ------------------------------------------------------------------

    @property
    def warnings(self) -> List[ExtractionWarning]:
        """Snapshot of all recorded ExtractionWarning objects."""
        with self._lock:
            return list(self._warnings)

    @property
    def gaps(self) -> List[CoverageGap]:
        """Snapshot of all recorded CoverageGap objects."""
        with self._lock:
            return list(self._gaps)

    # ------------------------------------------------------------------
    # Public API — summary
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, object]:
        """
        Return a plain-dict summary of the current state.

        Returns
        -------
        dict with keys:
            ``"warnings"``: total warning count (int)
            ``"gaps"``: total gap count (int)
            ``"gap_file_ids"``: sorted list of file_ids that have gaps (List[str])
        """
        with self._lock:
            gap_file_ids = sorted({g.file_id for g in self._gaps})
            return {
                "warnings": len(self._warnings),
                "gaps": len(self._gaps),
                "gap_file_ids": gap_file_ids,
            }
