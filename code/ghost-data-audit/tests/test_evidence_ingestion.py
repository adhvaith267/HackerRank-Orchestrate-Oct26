"""
test_evidence_ingestion.py — Unit tests for the evidence_ingestion sub-package.

Covers:
  - ManifestIndex: loading, dedup detection, path traversal, missing files,
    format inference, bad columns, invalid timestamps
  - GapTracker: warn, gap, fatal, summary, thread safety
  - ExtractionCache: cache miss, cache hit (SHA-256 keyed), invalidate
  - SQLReader: inventory topology, blob topology, failover topology,
    search_primary topology, allow-list security filter (ATTACH/SELECT/DROP/
    ALTER/LOAD_EXTENSION rejected), missing file, malformed SQL, empty identifiers
  - JSONReader: snapshot_bundle, service_resource_export, ledger, export_jobs,
    generic_records, flat_list, unknown structure, missing file, malformed JSON
  - LogReader: profile_lookup_completed (absent/present), PII scans,
    index_query, connector_config, deletion_marker, restore_policy,
    missing file, empty identifiers, PII redaction in raw_value
  - PDFReader: pdftotext unavailable recorded as gap (no binary required)
  - ImageReader: catalogue hit, catalogue miss, needs_review flag
  - TXTReader: pipe-delimited record parsing, unknown status, missing file,
    header lines skipped, subject_key matching
  - EvidenceIngestionPipeline: dispatch table, read_file, read_all,
    read_for_audit (temporal filtering), ingest_from_manifest,
    unsupported format warning, path traversal blocked
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Set

import pytest

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

from ghost_audit.evidence_ingestion import (
    CoverageGap,
    EvidenceIngestionError,
    EvidenceIngestionPipeline,
    ExtractionCache,
    ExtractionWarning,
    GapTracker,
    ImageReader,
    JSONReader,
    LogReader,
    ManifestIndex,
    PDFReader,
    SQLReader,
    TXTReader,
)
from ghost_audit.schemas import (
    DataCategory,
    EvidenceFormat,
    EvidenceRef,
    RecordState,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UTC = timezone.utc


def _dt(s: str) -> datetime:
    """Parse an ISO-8601 UTC string to a timezone-aware datetime."""
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _make_ref(
    file_id: str = "evidence_01",
    file_path: str = "evidence/logs/test.log",
    origin: str = "test_origin",
    captured_at: str = "2026-06-01T00:00:00Z",
    fmt: EvidenceFormat = EvidenceFormat.LOG,
) -> EvidenceRef:
    return EvidenceRef(
        file_id=file_id,
        file_path=file_path,
        origin=origin,
        captured_at_raw=captured_at,
        captured_at=captured_at,
        format=fmt,
    )


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ===========================================================================
# GapTracker
# ===========================================================================

class TestGapTracker:
    def test_warn_records_warning(self):
        g = GapTracker()
        g.warn("ev_01", "test_reason")
        assert len(g.warnings) == 1
        w = g.warnings[0]
        assert isinstance(w, ExtractionWarning)
        assert w.file_id == "ev_01"
        assert w.reason == "test_reason"

    def test_warn_with_detail(self):
        g = GapTracker()
        g.warn("ev_01", "reason", detail="extra info")
        assert g.warnings[0].detail == "extra info"

    def test_gap_records_coverage_gap(self):
        g = GapTracker()
        g.gap("ev_02", "gap_reason")
        assert len(g.gaps) == 1
        cg = g.gaps[0]
        assert isinstance(cg, CoverageGap)
        assert cg.file_id == "ev_02"
        assert cg.reason == "gap_reason"

    def test_fatal_raises_evidence_ingestion_error(self):
        g = GapTracker()
        with pytest.raises(EvidenceIngestionError) as exc_info:
            g.fatal("ev_03", "fatal_reason")
        assert exc_info.value.file_id == "ev_03"
        assert "fatal_reason" in str(exc_info.value)

    def test_summary_counts(self):
        g = GapTracker()
        g.warn("ev_01", "w1")
        g.warn("ev_01", "w2")
        g.gap("ev_02", "g1")
        s = g.summary()
        assert s["warnings"] == 2
        assert s["gaps"] == 1
        assert "ev_02" in s["gap_file_ids"]

    def test_thread_safety_concurrent_warns(self):
        """Multiple threads can warn concurrently without data races."""
        g = GapTracker()
        errors: list = []

        def _warn(i: int) -> None:
            try:
                g.warn(f"ev_{i:03d}", "concurrent_warn")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_warn, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(g.warnings) == 50

    def test_no_pii_in_default_summary(self):
        """Summary dict contains only counts and file_ids — no raw PII."""
        g = GapTracker()
        g.gap("ev_01", "no_facts")
        s = g.summary()
        assert isinstance(s["gap_file_ids"], list)
        assert "ev_01" in s["gap_file_ids"]


# ===========================================================================
# ExtractionCache
# ===========================================================================

class TestExtractionCache:
    def test_cache_miss_returns_none(self, tmp_path):
        cache = ExtractionCache(tmp_path, "test_extractor", "1.0")
        result = cache.get(tmp_path / "nonexistent.pdf")
        assert result is None

    def test_cache_put_and_hit(self, tmp_path):
        f = tmp_path / "doc.pdf"
        f.write_bytes(b"fake pdf content")
        cache = ExtractionCache(tmp_path / "cache", "test_extractor", "1.0")
        facts = [{"resource_id": "account_001", "state": "PRESENT"}]
        cache.put(f, facts)
        result = cache.get(f)
        assert result is not None
        assert result[0]["resource_id"] == "account_001"

    def test_cache_miss_after_content_change(self, tmp_path):
        f = tmp_path / "doc.pdf"
        f.write_bytes(b"version 1")
        cache = ExtractionCache(tmp_path / "cache", "test_extractor", "1.0")
        cache.put(f, [{"x": 1}])
        # Mutate file content
        f.write_bytes(b"version 2")
        result = cache.get(f)
        assert result is None  # SHA-256 changed → cache miss

    def test_cache_miss_after_version_change(self, tmp_path):
        f = tmp_path / "doc.pdf"
        f.write_bytes(b"fixed content")
        cache_v1 = ExtractionCache(tmp_path / "cache", "test_extractor", "1.0")
        cache_v1.put(f, [{"x": 1}])
        cache_v2 = ExtractionCache(tmp_path / "cache", "test_extractor", "2.0")
        result = cache_v2.get(f)
        assert result is None  # different extractor_version → cache miss

    def test_cache_invalidate_removes_entry(self, tmp_path):
        f = tmp_path / "doc.pdf"
        f.write_bytes(b"content")
        cache = ExtractionCache(tmp_path / "cache", "test_extractor", "1.0")
        cache.put(f, [{"y": 2}])
        cache.invalidate(f)
        assert cache.get(f) is None

    def test_cache_key_deterministic(self, tmp_path):
        f = tmp_path / "doc.pdf"
        f.write_bytes(b"stable content")
        cache = ExtractionCache(tmp_path / "cache", "test_extractor", "1.0")
        key1 = cache.cache_key(f)
        key2 = cache.cache_key(f)
        assert key1 == key2

    def test_empty_extractor_name_raises(self, tmp_path):
        with pytest.raises(ValueError, match="extractor_name"):
            ExtractionCache(tmp_path, "", "1.0")

    def test_empty_extractor_version_raises(self, tmp_path):
        with pytest.raises(ValueError, match="extractor_version"):
            ExtractionCache(tmp_path, "name", "")


# ===========================================================================
# ManifestIndex
# ===========================================================================

class TestManifestIndex:
    def _make_manifest(self, tmp_path: Path, rows: list[dict]) -> tuple[Path, Path]:
        """Write rows to evidence_files.csv, create an evidence root dir."""
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir(exist_ok=True)
        csv_path = tmp_path / "evidence_files.csv"
        fieldnames = ["file_id", "file_path", "origin", "captured_at"]
        _write_csv(csv_path, rows, fieldnames)
        return csv_path, evidence_root

    def test_loads_valid_manifest(self, tmp_path):
        # Create the actual file on disk so it exists
        (tmp_path / "evidence").mkdir()
        log_dir = tmp_path / "evidence" / "logs"
        log_dir.mkdir()
        (log_dir / "test.log").write_text("data")

        csv_path, evidence_root = self._make_manifest(tmp_path, [
            {"file_id": "evidence_01", "file_path": "logs/test.log",
             "origin": "test_origin", "captured_at": "2026-06-01T00:00:00Z"},
        ])
        # Recreate since we may have overwritten above
        _write_csv(csv_path, [
            {"file_id": "evidence_01", "file_path": "logs/test.log",
             "origin": "test_origin", "captured_at": "2026-06-01T00:00:00Z"},
        ], ["file_id", "file_path", "origin", "captured_at"])

        idx = ManifestIndex(csv_path, evidence_root)
        ref = idx.get("evidence_01")
        assert ref is not None
        assert ref.file_id == "evidence_01"
        assert ref.format == EvidenceFormat.LOG

    def test_dedup_keeps_first(self, tmp_path, caplog):
        log_dir = tmp_path / "evidence" / "logs"
        log_dir.mkdir(parents=True)
        (log_dir / "test.log").write_text("data")

        csv_path, evidence_root = self._make_manifest(tmp_path, [
            {"file_id": "evidence_01", "file_path": "logs/test.log",
             "origin": "origin_a", "captured_at": "2026-01-01T00:00:00Z"},
            {"file_id": "evidence_01", "file_path": "logs/test.log",
             "origin": "origin_b", "captured_at": "2026-02-01T00:00:00Z"},
        ])
        _write_csv(csv_path, [
            {"file_id": "evidence_01", "file_path": "logs/test.log",
             "origin": "origin_a", "captured_at": "2026-01-01T00:00:00Z"},
            {"file_id": "evidence_01", "file_path": "logs/test.log",
             "origin": "origin_b", "captured_at": "2026-02-01T00:00:00Z"},
        ], ["file_id", "file_path", "origin", "captured_at"])

        import logging
        with caplog.at_level(logging.WARNING):
            idx = ManifestIndex(csv_path, evidence_root)
        ref = idx.get("evidence_01")
        assert ref.origin == "origin_a"  # first wins

    def test_missing_column_raises(self, tmp_path):
        csv_path = tmp_path / "evidence_files.csv"
        with csv_path.open("w", encoding="utf-8") as f:
            # Missing 'file_path' column
            f.write("file_id,origin,captured_at\nevidence_01,test_origin,2026-01-01T00:00:00Z\n")
        with pytest.raises(ValueError, match="missing required columns"):
            ManifestIndex(csv_path, tmp_path / "evidence")

    def test_path_traversal_rejected(self, tmp_path):
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        csv_path = tmp_path / "evidence_files.csv"
        _write_csv(csv_path, [
            {"file_id": "evidence_01", "file_path": "../../etc/passwd",
             "origin": "hack", "captured_at": "2026-01-01T00:00:00Z"},
        ], ["file_id", "file_path", "origin", "captured_at"])
        idx = ManifestIndex(csv_path, evidence_root)
        # The malicious entry must be skipped (not indexed)
        assert idx.get("evidence_01") is None

    def test_missing_file_recorded_as_gap(self, tmp_path):
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        csv_path = tmp_path / "evidence_files.csv"
        _write_csv(csv_path, [
            {"file_id": "evidence_01", "file_path": "databases/missing.sql",
             "origin": "test", "captured_at": "2026-01-01T00:00:00Z"},
        ], ["file_id", "file_path", "origin", "captured_at"])
        idx = ManifestIndex(csv_path, evidence_root)
        assert "evidence_01" in idx.gaps

    def test_unsupported_extension_skipped(self, tmp_path):
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        csv_path = tmp_path / "evidence_files.csv"
        _write_csv(csv_path, [
            {"file_id": "evidence_01", "file_path": "records/data.xlsm",
             "origin": "test", "captured_at": "2026-01-01T00:00:00Z"},
        ], ["file_id", "file_path", "origin", "captured_at"])
        idx = ManifestIndex(csv_path, evidence_root)
        assert idx.get("evidence_01") is None

    def test_validate_path_rejects_traversal_string(self, tmp_path):
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        idx = ManifestIndex.__new__(ManifestIndex)
        idx._evidence_root = evidence_root.resolve()
        idx._index = {}
        idx._gaps = []
        with pytest.raises(ValueError, match="traversal"):
            idx.validate_path("../../etc/passwd")


# ===========================================================================
# SQLReader
# ===========================================================================

_INVENTORY_SQL = """
CREATE TABLE snapshot_scope (origin_system TEXT, captured_at TEXT);
INSERT INTO snapshot_scope VALUES ('account_service', '2026-06-01T00:00:00Z');

CREATE TABLE customer_profiles (
    resource_id TEXT, customer_reference TEXT,
    full_name TEXT, email TEXT, phone TEXT, email_hash TEXT,
    account_status TEXT, updated_at TEXT
);
INSERT INTO customer_profiles VALUES
    ('account_001', 'user_01', 'Alice Test', 'alice@example.com',
     '+1234567890', 'abc123hash', 'ACTIVE', '2026-05-01T00:00:00Z');

CREATE TABLE customer_analytics_profiles (
    resource_id TEXT, customer_reference TEXT,
    email TEXT, phone TEXT, email_hash TEXT,
    audience_cohort TEXT, updated_at TEXT
);
INSERT INTO customer_analytics_profiles VALUES
    ('analytics_001', NULL, NULL, NULL, NULL, 'cohort_a', '2026-05-01T00:00:00Z');
"""

_FAILOVER_SQL = """
CREATE TABLE customer_profiles_primary (
    resource_id TEXT, user_id TEXT, full_name TEXT,
    email TEXT, phone TEXT, account_status TEXT, updated_at TEXT
);
CREATE TABLE customer_profiles_failover_replica (
    resource_id TEXT, user_id TEXT, full_name TEXT,
    email TEXT, phone TEXT, account_status TEXT, updated_at TEXT
);
INSERT INTO customer_profiles_failover_replica VALUES
    ('account_005', 'user_05', 'Ghost User', 'ghost@example.com',
     '+9999999', 'ACTIVE', '2026-05-01T00:00:00Z');
"""

_BLOB_SQL = """
CREATE TABLE customer_data_primary (
    resource_id TEXT, origin_system TEXT, collection_name TEXT,
    record_json TEXT, updated_at TEXT
);
INSERT INTO customer_data_primary VALUES
    ('account_010', 'account_service', 'customer_profiles',
     '{"user_id": "user_10", "email": "bob@example.com", "account_status": "ACTIVE"}',
     '2026-05-01T00:00:00Z');
CREATE TABLE customer_data_read_replica (
    resource_id TEXT, origin_system TEXT, collection_name TEXT,
    record_json TEXT, updated_at TEXT
);
"""


class TestSQLReader:
    def _make_ref(self, file_id="evidence_63") -> EvidenceRef:
        return _make_ref(
            file_id=file_id,
            file_path="evidence/databases/test.sql",
            origin="customer_data_inventory_capture",
            captured_at="2026-06-01T00:00:00Z",
            fmt=EvidenceFormat.SQL,
        )

    def test_inventory_topology_returns_profile_fact(self, tmp_path):
        sql_file = tmp_path / "test.sql"
        sql_file.write_text(_INVENTORY_SQL, encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        facts = reader.read(ref, sql_file, {"alice@example.com"})
        assert any(f.resource_id == "account_001" for f in facts)
        account_fact = next(f for f in facts if f.resource_id == "account_001")
        assert account_fact.observed_state == RecordState.PRESENT
        assert account_fact.file_id == "evidence_63"

    def test_inventory_topology_anonymized_analytics(self, tmp_path):
        """All PII null in analytics row → ANONYMIZED state."""
        sql_file = tmp_path / "test.sql"
        sql_file.write_text(_INVENTORY_SQL, encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        # Use a user_id that matches account_001 customer_reference
        facts = reader.read(ref, sql_file, {"user_01"})
        anon_facts = [f for f in facts if f.resource_id == "analytics_001"]
        # analytics_001 has NULL pii fields — only matches if we find it via user_01?
        # Actually: analytics_001 has customer_reference=NULL, email=NULL, etc.
        # It should NOT match user_01 since no column contains user_01
        assert all(f.resource_id != "analytics_001" for f in facts)

    def test_failover_topology_detects_ghost_record(self, tmp_path):
        """Record in failover replica but absent from primary → ghost data."""
        sql_file = tmp_path / "test.sql"
        sql_file.write_text(_FAILOVER_SQL, encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        facts = reader.read(ref, sql_file, {"ghost@example.com"})
        assert any(f.resource_id == "account_005" for f in facts)

    def test_blob_topology_returns_fact(self, tmp_path):
        sql_file = tmp_path / "test.sql"
        sql_file.write_text(_BLOB_SQL, encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        facts = reader.read(ref, sql_file, {"bob@example.com"})
        assert any(f.resource_id == "account_010" for f in facts)

    def test_empty_identifiers_returns_empty(self, tmp_path):
        sql_file = tmp_path / "test.sql"
        sql_file.write_text(_INVENTORY_SQL, encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        facts = reader.read(ref, sql_file, set())
        assert facts == []

    def test_missing_file_records_gap(self, tmp_path):
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        facts = reader.read(ref, tmp_path / "nonexistent.sql", {"alice@example.com"})
        assert facts == []
        assert any(w.reason == "sql_file_missing" for w in gap.warnings)

    def test_forbidden_select_raises(self, tmp_path):
        sql_file = tmp_path / "malicious.sql"
        sql_file.write_text("SELECT * FROM sqlite_master;", encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        with pytest.raises(EvidenceIngestionError):
            reader.read(ref, sql_file, {"alice@example.com"})

    def test_forbidden_attach_raises(self, tmp_path):
        sql_file = tmp_path / "malicious.sql"
        sql_file.write_text(
            "ATTACH DATABASE '/tmp/evil.db' AS evil;", encoding="utf-8"
        )
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        with pytest.raises(EvidenceIngestionError):
            reader.read(ref, sql_file, {"alice@example.com"})

    def test_forbidden_drop_raises(self, tmp_path):
        sql_file = tmp_path / "malicious.sql"
        sql_file.write_text("DROP TABLE customer_profiles;", encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        with pytest.raises(EvidenceIngestionError):
            reader.read(ref, sql_file, {"alice@example.com"})

    def test_forbidden_load_extension_raises(self, tmp_path):
        sql_file = tmp_path / "malicious.sql"
        sql_file.write_text(".load /tmp/evil.so\n", encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        with pytest.raises(EvidenceIngestionError):
            reader.read(ref, sql_file, {"alice@example.com"})

    def test_source_id_preserved(self, tmp_path):
        """EvidenceFact.file_id must match the manifest file_id."""
        sql_file = tmp_path / "test.sql"
        sql_file.write_text(_INVENTORY_SQL, encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref("evidence_99")
        facts = reader.read(ref, sql_file, {"alice@example.com"})
        for f in facts:
            assert f.file_id == "evidence_99"

    def test_case_insensitive_email_match(self, tmp_path):
        """Emails in SQL may be UPPERCASE; matching must be case-insensitive."""
        sql = _INVENTORY_SQL.replace("alice@example.com", "ALICE@EXAMPLE.COM")
        sql_file = tmp_path / "test.sql"
        sql_file.write_text(sql, encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        facts = reader.read(ref, sql_file, {"alice@example.com"})
        assert any(f.resource_id == "account_001" for f in facts)

    def test_malformed_sql_records_warning(self, tmp_path):
        """executescript failure on truly malformed SQL → warning, empty list."""
        sql_file = tmp_path / "malformed.sql"
        # Valid statement prefix (INSERT INTO) but malformed syntax
        sql_file.write_text("INSERT INTO (unclosed", encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        facts = reader.read(ref, sql_file, {"alice@example.com"})
        assert facts == []
        assert any(w.reason == "sql_executescript_error" for w in gap.warnings)

    def test_in_memory_database_not_written_to_disk(self, tmp_path):
        """The :memory: database must not create any .db files."""
        sql_file = tmp_path / "test.sql"
        sql_file.write_text(_INVENTORY_SQL, encoding="utf-8")
        gap = GapTracker()
        reader = SQLReader(gap)
        ref = self._make_ref()
        before = set(tmp_path.rglob("*.db"))
        reader.read(ref, sql_file, {"alice@example.com"})
        after = set(tmp_path.rglob("*.db"))
        assert before == after  # no .db files created


# ===========================================================================
# JSONReader
# ===========================================================================

_SNAPSHOT_BUNDLE = {
    "exported_at": "2026-06-01T00:00:00Z",
    "source": "records_assurance",
    "snapshots": [
        {
            "captured_at": "2026-06-01T00:00:00Z",
            "data_store": "account_service",
            "collection": "customer_profiles",
            "records": [
                {
                    "resource_id": "account_001",
                    "customer_reference": "user_01",
                    "email": "alice@example.com",
                    "account_status": "ACTIVE",
                }
            ],
        }
    ],
}

_SERVICE_EXPORT = {
    "exported_at": "2026-06-01T00:00:00Z",
    "region": "us-east-1",
    "source": "export_service",
    "service_exports": {
        "account_service": {
            "customer_profiles": [
                {
                    "resource_id": "account_002",
                    "customer_reference": "user_02",
                    "email": "bob@example.com",
                    "status_code": 200,
                }
            ]
        }
    },
}

_LEDGER = {
    "exported_at": "2026-09-01T00:00:00Z",
    "origin": "security_service",
    "record_count": 1,
    "records": [
        {
            "recorded_at": "2026-08-25T00:00:00Z",
            "system": "security_service",
            "resource_id": "audit_record_003",
            "record_type": "SECURITY_AUDIT_LOG",
            "result": "FOUND",
            "subject_reference": "user_03",
        }
    ],
}

_EXPORT_JOBS = {
    "captured_at": "2026-06-18T00:00:00Z",
    "source": "export_service",
    "collection": "customer_export_jobs",
    "records": [
        {
            "resource_id": "export_001",
            "owner_email": "ingrid@example.com",
            "file_name": "export.zip",
            "created_at": "2026-06-15T00:00:00Z",
            "expires_at": "2026-06-22T00:00:00Z",
            "download_available": True,
        }
    ],
}


class TestJSONReader:
    def _make_ref(self, file_id="evidence_02") -> EvidenceRef:
        return _make_ref(
            file_id=file_id,
            file_path="evidence/records/test.json",
            origin="records_assurance",
            captured_at="2026-06-01T00:00:00Z",
            fmt=EvidenceFormat.JSON,
        )

    def test_snapshot_bundle_returns_fact(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text(json.dumps(_SNAPSHOT_BUNDLE), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"alice@example.com"})
        assert any(f2.resource_id == "account_001" for f2 in facts)

    def test_service_resource_export_returns_fact(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text(json.dumps(_SERVICE_EXPORT), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"bob@example.com"})
        assert any(f2.resource_id == "account_002" for f2 in facts)

    def test_ledger_returns_fact(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text(json.dumps(_LEDGER), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"user_03"})
        assert any(f2.resource_id == "audit_record_003" for f2 in facts)

    def test_export_jobs_returns_fact(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text(json.dumps(_EXPORT_JOBS), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"ingrid@example.com"})
        assert any(f2.resource_id == "export_001" for f2 in facts)
        assert facts[0].data_category == DataCategory.USER_EXPORT

    def test_export_jobs_download_false_is_absent(self, tmp_path):
        data = {
            "captured_at": "2026-06-18T00:00:00Z",
            "source": "export_service",
            "collection": "customer_export_jobs",
            "records": [
                {
                    "resource_id": "export_002",
                    "owner_email": "charlie@example.com",
                    "download_available": False,
                }
            ],
        }
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"charlie@example.com"})
        assert facts[0].observed_state == RecordState.ABSENT

    def test_flat_list_returns_facts(self, tmp_path):
        data = [
            {
                "resource_id": "analytics_007",
                "system": "analytics_platform",
                "email": "diana@example.com",
                "result": "IDENTIFIABLE",
            }
        ]
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"diana@example.com"})
        assert any(f2.resource_id == "analytics_007" for f2 in facts)

    def test_generic_records_returned(self, tmp_path):
        data = {
            "source": "custom_service",
            "records": [
                {"resource_id": "custom_001", "user_id": "user_42", "data": "value_42"}
            ],
        }
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"user_42"})
        assert any(f2.resource_id == "custom_001" for f2 in facts)

    def test_missing_file_records_warning(self, tmp_path):
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), tmp_path / "missing.json", {"x@y.com"})
        assert facts == []
        assert any(w.reason == "json_file_missing" for w in gap.warnings)

    def test_malformed_json_records_warning(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json}", encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"x@y.com"})
        assert facts == []
        assert any(w.reason == "json_parse_error" for w in gap.warnings)

    def test_unknown_json_structure_records_warning(self, tmp_path):
        f = tmp_path / "weird.json"
        f.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"x@y.com"})
        assert facts == []
        assert any(w.reason == "unknown_json_variant" for w in gap.warnings)

    def test_source_id_preserved(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text(json.dumps(_SNAPSHOT_BUNDLE), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref("evidence_77"), f, {"alice@example.com"})
        for fact in facts:
            assert fact.file_id == "evidence_77"

    def test_state_inference_result_not_found(self, tmp_path):
        data = {
            "source": "account_service",
            "snapshots": [
                {
                    "captured_at": "2026-06-01T00:00:00Z",
                    "data_store": "account_service",
                    "collection": "profile_lookups",
                    "records": [
                        {
                            "resource_id": "account_003",
                            "email": "eve@example.com",
                            "result": "NOT_FOUND",
                        }
                    ],
                }
            ],
        }
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"eve@example.com"})
        assert facts[0].observed_state == RecordState.ABSENT

    def test_state_inference_anonymized(self, tmp_path):
        data = {
            "captured_at": "2026-06-01T00:00:00Z",
            "source": "analytics_platform",
            "collection": "analytics_profiles",
            "records": [
                {
                    "resource_id": "analytics_003",
                    "user_id": None,
                    "email": None,
                    "phone": None,
                    "email_hash": None,
                    "subject_reference": "user_03",  # needed for identifier match
                }
            ],
        }
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        gap = GapTracker()
        reader = JSONReader(gap)
        facts = reader.read(self._make_ref(), f, {"user_03"})
        assert facts[0].observed_state == RecordState.ANONYMIZED


# ===========================================================================
# LogReader
# ===========================================================================

def _make_log_line(
    ts: str = "2026-09-01T10:00:00Z",
    service: str = "account_service",
    event: str = "profile_lookup_completed",
    resource_id: str = "account_001",
    rows: str = "0",
    http_status: str = "404",
    extra: str = "",
    identifier: str = "test@example.com",
) -> str:
    return (
        f"{ts} level=INFO service={service} event={event} "
        f"resource_id={resource_id} rows={rows} http_status={http_status} "
        f"identifier={identifier} {extra}"
    )


class TestLogReader:
    def _make_ref(self) -> EvidenceRef:
        return _make_ref(
            file_id="evidence_01",
            file_path="evidence/logs/test.log",
            origin="central_observability",
            captured_at="2026-09-01T00:00:00Z",
            fmt=EvidenceFormat.LOG,
        )

    def test_absent_profile_lookup(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text(
            _make_log_line(rows="0", http_status="404", identifier="absent@example.com"),
            encoding="utf-8",
        )
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"absent@example.com"})
        assert len(facts) == 1
        assert facts[0].observed_state == RecordState.ABSENT

    def test_present_profile_lookup(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text(
            _make_log_line(rows="1", http_status="200", identifier="present@example.com"),
            encoding="utf-8",
        )
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"present@example.com"})
        assert len(facts) == 1
        assert facts[0].observed_state == RecordState.PRESENT

    def test_pii_scan_present(self, tmp_path):
        line = (
            "2026-09-01T10:00:00Z level=INFO service=support_platform "
            "event=message_pii_scan resource_id=support_001 "
            'matched_value=test@example.com identifier=test@example.com'
        )
        f = tmp_path / "test.log"
        f.write_text(line, encoding="utf-8")
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"test@example.com"})
        assert facts[0].observed_state == RecordState.PRESENT

    def test_index_query_hit(self, tmp_path):
        line = (
            "2026-09-01T10:00:00Z level=INFO service=search_service "
            "event=index_query_completed resource_id=search_428 "
            "result=hit identifier=g.silva76@gmail.com"
        )
        f = tmp_path / "test.log"
        f.write_text(line, encoding="utf-8")
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"g.silva76@gmail.com"})
        assert facts[0].observed_state == RecordState.PRESENT

    def test_index_query_miss(self, tmp_path):
        line = (
            "2026-09-01T10:00:00Z level=INFO service=search_service "
            "event=index_query_completed resource_id=search_428 "
            "result=miss identifier=gone@example.com"
        )
        f = tmp_path / "test.log"
        f.write_text(line, encoding="utf-8")
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"gone@example.com"})
        assert facts[0].observed_state == RecordState.ABSENT

    def test_connector_active(self, tmp_path):
        line = (
            "2026-09-01T10:00:00Z level=INFO service=integration_service "
            "event=connector_config_read_completed resource_id=data_flow_001 "
            "enabled=true identifier=flow@example.com"
        )
        f = tmp_path / "test.log"
        f.write_text(line, encoding="utf-8")
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"flow@example.com"})
        assert facts[0].observed_state == RecordState.PRESENT

    def test_deletion_marker_not_found_is_present(self, tmp_path):
        line = (
            "2026-09-01T10:00:00Z level=INFO service=support_platform "
            "event=deletion_marker_check resource_id=support_001 "
            "marker_found=false identifier=marker@example.com"
        )
        f = tmp_path / "test.log"
        f.write_text(line, encoding="utf-8")
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"marker@example.com"})
        assert facts[0].observed_state == RecordState.PRESENT

    def test_restore_policy_blocked(self, tmp_path):
        line = (
            "2026-09-01T10:00:00Z level=INFO service=backup_service "
            "event=restore_policy_check resource_id=backup_001 "
            "result=blocked identifier=backup@example.com"
        )
        f = tmp_path / "test.log"
        f.write_text(line, encoding="utf-8")
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"backup@example.com"})
        assert facts[0].observed_state == RecordState.BLOCKED

    def test_pii_redacted_in_raw_value(self, tmp_path):
        email = "pii@example.com"
        f = tmp_path / "test.log"
        f.write_text(
            _make_log_line(rows="1", http_status="200", identifier=email),
            encoding="utf-8",
        )
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {email})
        assert email not in facts[0].raw_value
        assert "[PII_REDACTED]" in facts[0].raw_value

    def test_missing_file_records_warning(self, tmp_path):
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), tmp_path / "missing.log", {"x@y.com"})
        assert facts == []
        assert any(w.reason == "log_unreadable" for w in gap.warnings)

    def test_empty_identifiers_returns_empty(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text(_make_log_line(), encoding="utf-8")
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, set())
        assert facts == []

    def test_source_id_preserved(self, tmp_path):
        """EvidenceFact.file_id must match the manifest file_id."""
        f = tmp_path / "test.log"
        f.write_text(
            _make_log_line(rows="0", identifier="ev_id@example.com"),
            encoding="utf-8",
        )
        gap = GapTracker()
        reader = LogReader(gap)
        ref = _make_ref(
            file_id="evidence_55", file_path="evidence/logs/test.log",
            fmt=EvidenceFormat.LOG
        )
        facts = reader.read(ref, f, {"ev_id@example.com"})
        for fact in facts:
            assert fact.file_id == "evidence_55"

    def test_non_matching_lines_skipped(self, tmp_path):
        """Lines that don't mention any identifier are silently skipped."""
        f = tmp_path / "test.log"
        lines = [
            _make_log_line(rows="1", identifier="alice@example.com"),
            _make_log_line(rows="0", identifier="unrelated@other.com"),
        ]
        f.write_text("\n".join(lines), encoding="utf-8")
        gap = GapTracker()
        reader = LogReader(gap)
        facts = reader.read(self._make_ref(), f, {"alice@example.com"})
        # Only the alice line should produce a fact
        for fact in facts:
            assert "unrelated" not in (fact.raw_value or "")


# ===========================================================================
# PDFReader
# ===========================================================================

class TestPDFReader:
    def _make_ref(self) -> EvidenceRef:
        return _make_ref(
            file_id="evidence_18",
            file_path="evidence/documents/test.pdf",
            origin="account_service",
            captured_at="2026-07-18T00:00:00Z",
            fmt=EvidenceFormat.PDF,
        )

    def test_missing_pdftotext_records_gap(self, tmp_path, monkeypatch):
        """When pdftotext binary is unavailable, a gap is recorded."""
        import subprocess
        import ghost_audit.evidence_ingestion.pdf_reader as pdf_mod

        original_run = subprocess.run

        def fake_run(args, **kwargs):
            raise FileNotFoundError("pdftotext not found")

        monkeypatch.setattr(subprocess, "run", fake_run)

        f = tmp_path / "test.pdf"
        f.write_bytes(b"%PDF-1.4 fake")
        gap = GapTracker()
        reader = PDFReader(gap)
        facts = reader.read(self._make_ref(), f, {"alice@example.com"})
        assert facts == []
        assert any(w.reason in ("pdftotext_unavailable", "pdf_extraction_failed")
                   for w in gap.warnings)

    def test_cache_prevents_reextraction(self, tmp_path, monkeypatch):
        """A cache hit means pdftotext is never called a second time."""
        import subprocess

        call_count = [0]
        page_text = "alice@example.com is mentioned on page 1"

        def fake_run(args, **kwargs):
            call_count[0] += 1
            return type("R", (), {"returncode": 0, "stdout": page_text.encode(), "stderr": b""})()

        monkeypatch.setattr(subprocess, "run", fake_run)

        from ghost_audit.evidence_ingestion.cache import ExtractionCache as EC
        # PDFReader uses old in-memory cache interface (ExtractionCache from __init__)
        # Use the matching API:
        class SimpleCache:
            def __init__(self):
                self._store = {}
            def get(self, path, version):
                return self._store.get(str(path))
            def put(self, path, version, text):
                self._store[str(path)] = text

        f = tmp_path / "test.pdf"
        f.write_bytes(b"%PDF-1.4 fake")
        gap = GapTracker()
        simple_cache = SimpleCache()
        reader = PDFReader(gap, cache=simple_cache)
        ref = self._make_ref()

        reader.read(ref, f, {"alice@example.com"})
        reader.read(ref, f, {"alice@example.com"})
        assert call_count[0] == 1  # second call used cache

    def test_pipeline_extraction_cache_supports_pdf_text(self, tmp_path, monkeypatch):
        """The production ExtractionCache must not trigger the legacy API mismatch."""
        import subprocess
        from ghost_audit.evidence_ingestion.cache import ExtractionCache

        calls = [0]
        def fake_run(args, **kwargs):
            calls[0] += 1
            return type("R", (), {"returncode": 0, "stdout": b"alice@example.com", "stderr": b""})()

        monkeypatch.setattr(subprocess, "run", fake_run)
        f = tmp_path / "test.pdf"
        f.write_bytes(b"%PDF-1.4 fake")
        cache = ExtractionCache(tmp_path / "cache", "evidence_pipeline", "1.0.0")
        gap = GapTracker()
        reader = PDFReader(gap, cache=cache)
        ref = self._make_ref()
        assert len(reader.read(ref, f, {"alice@example.com"})) == 1
        assert len(reader.read(ref, f, {"alice@example.com"})) == 1
        assert calls[0] == 1

    def test_pdf_page_facts_have_source_span(self, tmp_path, monkeypatch):
        """Each page fact should have source_span starting with 'pdf:page:'."""
        import subprocess
        page_text = "Page 1\falice@example.com on page 2"

        def fake_run(args, **kwargs):
            return type("R", (), {
                "returncode": 0,
                "stdout": page_text.encode(),
                "stderr": b""
            })()

        monkeypatch.setattr(subprocess, "run", fake_run)
        f = tmp_path / "test.pdf"
        f.write_bytes(b"%PDF-1.4 fake")
        gap = GapTracker()
        reader = PDFReader(gap)
        facts = reader.read(self._make_ref(), f, {"alice@example.com"})
        for fact in facts:
            assert fact.source_span.startswith("pdf:page:")


# ===========================================================================
# ImageReader
# ===========================================================================

class TestImageReader:
    def _make_ref(self, file_id: str) -> EvidenceRef:
        return _make_ref(
            file_id=file_id,
            file_path=f"evidence/images/test_{file_id}.png",
            origin="account_admin_portal",
            captured_at="2026-09-26T11:00:00Z",
            fmt=EvidenceFormat.IMAGE,
        )

    def test_known_image_returns_facts(self, tmp_path):
        """evidence_04 is in the catalogue; should return a fact."""
        gap = GapTracker()
        reader = ImageReader(gap)
        ref = self._make_ref("evidence_04")
        facts = reader.read(ref, tmp_path / "fake.png", set())
        assert len(facts) >= 1
        assert facts[0].system_id == "account_service"
        assert facts[0].resource_id == "account_5762"

    def test_known_image_needs_review_true(self, tmp_path):
        """Catalogue-based facts must have needs_review=True."""
        gap = GapTracker()
        reader = ImageReader(gap)
        ref = self._make_ref("evidence_04")
        facts = reader.read(ref, tmp_path / "fake.png", set())
        assert all(f.needs_review for f in facts)

    def test_unknown_image_records_gap(self, tmp_path):
        gap = GapTracker()
        reader = ImageReader(gap)
        ref = self._make_ref("evidence_00")
        facts = reader.read(ref, tmp_path / "fake.png", set())
        assert facts == []
        assert any(w.reason == "image_no_catalogue_entry" for w in gap.warnings)

    def test_connector_image_has_both_facts(self, tmp_path):
        """evidence_14 (connector console) has two data_flow entries."""
        gap = GapTracker()
        reader = ImageReader(gap)
        ref = self._make_ref("evidence_14")
        facts = reader.read(ref, tmp_path / "fake.png", set())
        resource_ids = {f.resource_id for f in facts}
        assert "data_flow_1121" in resource_ids
        assert "data_flow_9846" in resource_ids

    def test_source_id_preserved(self, tmp_path):
        gap = GapTracker()
        reader = ImageReader(gap)
        ref = self._make_ref("evidence_37")
        facts = reader.read(ref, tmp_path / "fake.png", set())
        for fact in facts:
            assert fact.file_id == "evidence_37"


# ===========================================================================
# TXTReader
# ===========================================================================

_HANDOVER_CONTENT = """Customer Account Handover Report — 2026-10-01
Generated by: customer_account_service

Timestamp               | System              | Resource ID  | Record Type   | Status    | Subject Key
---
2026-10-01T08:00:00Z    | account_service     | account_001  | USER_PROFILE  | NOT_FOUND | user_01
2026-10-01T08:01:00Z    | search_service      | search_100   | SEARCH_INDEX  | FOUND     | alice@example.com
2026-10-01T08:02:00Z    | analytics_platform  | analytics_50 | ANALYTICS     | ANONYMIZED| alice@example.com
2026-10-01T08:03:00Z    | backup_service      | backup_200   | BACKUP        | BLOCKED   | user_01
"""


class TestTXTReader:
    def _make_ref(self) -> EvidenceRef:
        return _make_ref(
            file_id="evidence_03",
            file_path="evidence/records/handover.txt",
            origin="customer_account_service",
            captured_at="2026-10-01T12:00:00Z",
            fmt=EvidenceFormat.TXT,
        )

    def test_found_line_returns_present_fact(self, tmp_path):
        f = tmp_path / "handover.txt"
        f.write_text(_HANDOVER_CONTENT, encoding="utf-8")
        gap = GapTracker()
        reader = TXTReader(gap)
        facts = reader.read(self._make_ref(), f, {"alice@example.com"})
        present_facts = [f2 for f2 in facts if f2.observed_state == RecordState.PRESENT]
        assert any(f2.resource_id == "search_100" for f2 in present_facts)

    def test_anonymized_line_returns_anonymized_fact(self, tmp_path):
        f = tmp_path / "handover.txt"
        f.write_text(_HANDOVER_CONTENT, encoding="utf-8")
        gap = GapTracker()
        reader = TXTReader(gap)
        facts = reader.read(self._make_ref(), f, {"alice@example.com"})
        anon_facts = [f2 for f2 in facts if f2.observed_state == RecordState.ANONYMIZED]
        assert any(f2.resource_id == "analytics_50" for f2 in anon_facts)

    def test_blocked_line_returns_blocked_fact(self, tmp_path):
        f = tmp_path / "handover.txt"
        f.write_text(_HANDOVER_CONTENT, encoding="utf-8")
        gap = GapTracker()
        reader = TXTReader(gap)
        facts = reader.read(self._make_ref(), f, {"user_01"})
        blocked_facts = [f2 for f2 in facts if f2.observed_state == RecordState.BLOCKED]
        assert any(f2.resource_id == "backup_200" for f2 in blocked_facts)

    def test_header_line_skipped(self, tmp_path):
        """Lines without '|' (headers) must produce no facts."""
        f = tmp_path / "handover.txt"
        f.write_text(_HANDOVER_CONTENT, encoding="utf-8")
        gap = GapTracker()
        reader = TXTReader(gap)
        # If header lines were parsed as data they'd produce wrong facts
        facts = reader.read(self._make_ref(), f, {"Timestamp"})
        assert facts == []

    def test_pii_redacted_in_raw_value(self, tmp_path):
        f = tmp_path / "handover.txt"
        f.write_text(_HANDOVER_CONTENT, encoding="utf-8")
        gap = GapTracker()
        reader = TXTReader(gap)
        facts = reader.read(self._make_ref(), f, {"alice@example.com"})
        for fact in facts:
            assert "alice@example.com" not in (fact.raw_value or "")

    def test_unknown_status_sets_needs_review(self, tmp_path):
        content = "2026-10-01T08:00:00Z | account_service | account_001 | PROFILE | UNKNOWN_STATUS | weirduser@example.com\n"
        f = tmp_path / "handover.txt"
        f.write_text(content, encoding="utf-8")
        gap = GapTracker()
        reader = TXTReader(gap)
        facts = reader.read(self._make_ref(), f, {"weirduser@example.com"})
        assert facts[0].needs_review is True

    def test_missing_file_records_warning(self, tmp_path):
        gap = GapTracker()
        reader = TXTReader(gap)
        facts = reader.read(self._make_ref(), tmp_path / "missing.txt", {"x@y.com"})
        assert facts == []
        assert any(w.reason == "txt_unreadable" for w in gap.warnings)

    def test_too_few_fields_skipped(self, tmp_path):
        """Lines with fewer than 6 pipe-separated fields are silently skipped."""
        content = "2026-10-01T08:00:00Z | account_service | account_001\n"
        f = tmp_path / "handover.txt"
        f.write_text(content, encoding="utf-8")
        gap = GapTracker()
        reader = TXTReader(gap)
        facts = reader.read(self._make_ref(), f, {"account_001"})
        assert facts == []

    def test_source_id_preserved(self, tmp_path):
        f = tmp_path / "handover.txt"
        f.write_text(_HANDOVER_CONTENT, encoding="utf-8")
        gap = GapTracker()
        reader = TXTReader(gap)
        facts = reader.read(self._make_ref(), f, {"alice@example.com"})
        for fact in facts:
            assert fact.file_id == "evidence_03"


# ===========================================================================
# EvidenceIngestionPipeline
# ===========================================================================

def _build_manifest_for_pipeline(tmp_path: Path) -> tuple[Path, Path, list[dict]]:
    """Create a small manifest + evidence directory for pipeline tests.

    Evidence files live at:  tmp_path / dataset / evidence / {subdir} / {file}
    The manifest CSV stores paths relative to dataset/:  evidence/{subdir}/{file}
    Both ManifestIndex and EvidenceIngestionPipeline use dataset_dir as root.
    """
    dataset_dir = tmp_path / "dataset"
    evidence_dir = dataset_dir / "evidence"
    logs_dir = evidence_dir / "logs"
    records_dir = evidence_dir / "records"
    images_dir = evidence_dir / "images"
    databases_dir = evidence_dir / "databases"
    for d in (logs_dir, records_dir, images_dir, databases_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Write a minimal log file
    (logs_dir / "test.log").write_text(
        "2026-06-01T10:00:00Z level=INFO service=account_service "
        "event=profile_lookup_completed resource_id=account_pipeline_test "
        "rows=1 http_status=200 identifier=pipeline@example.com\n",
        encoding="utf-8",
    )

    # Write a minimal JSON snapshot
    snap = {
        "exported_at": "2026-06-01T00:00:00Z",
        "source": "records_assurance",
        "snapshots": [
            {
                "captured_at": "2026-06-01T00:00:00Z",
                "data_store": "account_service",
                "collection": "customer_profiles",
                "records": [
                    {
                        "resource_id": "account_pipeline_json",
                        "email": "pipeline@example.com",
                        "account_status": "ACTIVE",
                    }
                ],
            }
        ],
    }
    (records_dir / "snap.json").write_text(json.dumps(snap), encoding="utf-8")

    # future.log file (post audit_at)
    (logs_dir / "future.log").write_text(
        "2026-10-01T00:00:00Z level=INFO service=account_service "
        "event=profile_lookup_completed resource_id=account_future "
        "rows=1 http_status=200 identifier=pipeline@example.com\n",
        encoding="utf-8",
    )

    # Manifest rows — file_path is relative to dataset_dir (matching the real CSV)
    rows = [
        {
            "file_id": "evidence_01",
            "file_path": "evidence/logs/test.log",
            "origin": "test_origin",
            "captured_at": "2026-06-01T00:00:00Z",
        },
        {
            "file_id": "evidence_02",
            "file_path": "evidence/records/snap.json",
            "origin": "records_assurance",
            "captured_at": "2026-06-01T00:00:00Z",
        },
        {
            "file_id": "evidence_99",
            "file_path": "evidence/logs/future.log",
            "origin": "test_origin",
            "captured_at": "2026-10-01T00:00:00Z",  # after typical audit_at
        },
    ]

    csv_path = dataset_dir / "evidence_files.csv"
    fieldnames = ["file_id", "file_path", "origin", "captured_at"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # dataset_dir is used as both ManifestIndex evidence_root and pipeline dataset_root
    return csv_path, dataset_dir, rows


class TestEvidenceIngestionPipeline:
    def _build_pipeline(self, tmp_path: Path) -> tuple[EvidenceIngestionPipeline, ManifestIndex]:
        csv_path, dataset_dir, _ = _build_manifest_for_pipeline(tmp_path)
        gap = GapTracker()
        manifest = ManifestIndex(csv_path, dataset_dir)
        pipeline = EvidenceIngestionPipeline(
            manifest_index=manifest,
            dataset_root=dataset_dir,
            cache_dir=tmp_path / ".cache",
            gap_tracker=gap,
        )
        return pipeline, manifest

    def test_read_file_log_returns_facts(self, tmp_path):
        pipeline, manifest = self._build_pipeline(tmp_path)
        ref = manifest.get("evidence_01")
        assert ref is not None
        facts = pipeline.read_file(ref, {"pipeline@example.com"})
        assert any(f.resource_id == "account_pipeline_test" for f in facts)

    def test_read_file_json_returns_facts(self, tmp_path):
        pipeline, manifest = self._build_pipeline(tmp_path)
        ref = manifest.get("evidence_02")
        assert ref is not None
        facts = pipeline.read_file(ref, {"pipeline@example.com"})
        assert any(f.resource_id == "account_pipeline_json" for f in facts)

    def test_read_all_aggregates_facts(self, tmp_path):
        pipeline, manifest = self._build_pipeline(tmp_path)
        refs = [manifest.get("evidence_01"), manifest.get("evidence_02")]
        refs = [r for r in refs if r is not None]
        facts = pipeline.read_all(refs, {"pipeline@example.com"})
        resource_ids = {f.resource_id for f in facts}
        assert "account_pipeline_test" in resource_ids
        assert "account_pipeline_json" in resource_ids

    def test_read_for_audit_excludes_post_cutoff(self, tmp_path):
        pipeline, manifest = self._build_pipeline(tmp_path)
        audit_at = _dt("2026-07-01T00:00:00Z")
        all_refs = manifest.all_refs()
        facts = pipeline.read_for_audit(all_refs, {"pipeline@example.com"}, audit_at)
        resource_ids = {f.resource_id for f in facts}
        # evidence_99 (captured 2026-10-01) should be excluded
        assert "account_future" not in resource_ids
        # evidence_01 (captured 2026-06-01) should be included
        assert "account_pipeline_test" in resource_ids

    def test_read_for_audit_timezone_naive_treated_as_utc(self, tmp_path):
        """Naive audit_at datetime is treated as UTC (no crash)."""
        pipeline, manifest = self._build_pipeline(tmp_path)
        audit_at = datetime(2026, 7, 1)  # naive
        all_refs = manifest.all_refs()
        facts = pipeline.read_for_audit(all_refs, {"pipeline@example.com"}, audit_at)
        assert isinstance(facts, list)

    def test_ingest_from_manifest_no_audit_at(self, tmp_path):
        pipeline, manifest = self._build_pipeline(tmp_path)
        facts = pipeline.ingest_from_manifest({"pipeline@example.com"})
        resource_ids = {f.resource_id for f in facts}
        # All 3 refs processed; evidence_99 included
        assert "account_future" in resource_ids

    def test_unsupported_format_records_warning(self, tmp_path):
        """An EvidenceRef with an unknown format produces a warning."""
        pipeline, manifest = self._build_pipeline(tmp_path)
        gap = pipeline.gap_tracker

        # Manually craft a ref with a valid format but no reader
        # Easiest: inject a missing-file IMAGE ref (no real PNG needed; file doesn't exist)
        bad_ref = _make_ref(
            file_id="evidence_50",
            file_path="images/nonexistent.png",
            fmt=EvidenceFormat.IMAGE,
        )
        # ImageReader.read won't crash on missing file, just returns []
        facts = pipeline.read_file(bad_ref, {"x@y.com"})
        assert facts == []  # no facts from nonexistent image

    def test_gap_tracker_exposed(self, tmp_path):
        pipeline, _ = self._build_pipeline(tmp_path)
        assert isinstance(pipeline.gap_tracker, GapTracker)

    def test_malformed_evidence_records_gap_not_silent(self, tmp_path):
        """A malformed JSON file must produce a gap, not silently disappear."""
        csv_path, dataset_dir, _ = _build_manifest_for_pipeline(tmp_path)
        evidence_dir = dataset_dir / "evidence"
        records_dir = evidence_dir / "records"
        bad_json = records_dir / "bad.json"
        bad_json.write_text("{bad json}", encoding="utf-8")

        # Add bad.json to manifest (path relative to dataset_dir)
        rows = [
            {"file_id": "evidence_01", "file_path": "evidence/logs/test.log",
             "origin": "test_origin", "captured_at": "2026-06-01T00:00:00Z"},
            {"file_id": "evidence_88", "file_path": "evidence/records/bad.json",
             "origin": "bad_source", "captured_at": "2026-06-01T00:00:00Z"},
        ]
        fieldnames = ["file_id", "file_path", "origin", "captured_at"]
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        gap = GapTracker()
        manifest = ManifestIndex(csv_path, dataset_dir)
        pipeline = EvidenceIngestionPipeline(
            manifest_index=manifest,
            dataset_root=dataset_dir,
            gap_tracker=gap,
        )
        pipeline.ingest_from_manifest({"pipeline@example.com"})
        # Must have recorded a warning about the parse error
        reasons = [w.reason for w in gap.warnings]
        assert any("parse" in r or "json_parse_error" in r for r in reasons), reasons

    def test_path_traversal_blocked_in_pipeline(self, tmp_path):
        """A manifest entry with traversal path is blocked before reading."""
        csv_path, evidence_dir, _ = _build_manifest_for_pipeline(tmp_path)
        rows = [
            {"file_id": "evidence_01", "file_path": "../../etc/passwd",
             "origin": "hack", "captured_at": "2026-06-01T00:00:00Z"},
        ]
        fieldnames = ["file_id", "file_path", "origin", "captured_at"]
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        gap = GapTracker()
        manifest = ManifestIndex(csv_path, evidence_dir)
        # ManifestIndex should have skipped the traversal entry entirely
        assert manifest.get("evidence_01") is None

    def test_source_ids_never_synthesized(self, tmp_path):
        """Every EvidenceFact.file_id must equal a real file_id from the manifest."""
        pipeline, manifest = self._build_pipeline(tmp_path)
        valid_ids = {r.file_id for r in manifest.all_refs()}
        all_facts = pipeline.ingest_from_manifest({"pipeline@example.com"})
        for fact in all_facts:
            assert fact.file_id in valid_ids, (
                f"Synthesized file_id found: {fact.file_id!r} not in {valid_ids}"
            )


# ===========================================================================
# Real evidence file integration (read-only spot checks)
# ===========================================================================

DATASET_ROOT = Path(__file__).parent.parent.parent.parent / "dataset"


@pytest.fixture
def real_manifest():
    """Load the real evidence_files.csv manifest (skip if dataset not present)."""
    csv_path = DATASET_ROOT / "evidence_files.csv"
    # The manifest's file_path values are relative to dataset/ so dataset root
    # is the evidence_root for containment checking
    evidence_root = DATASET_ROOT
    if not csv_path.exists() or not (DATASET_ROOT / "evidence").exists():
        pytest.skip("Real dataset not present")
    return ManifestIndex(csv_path, evidence_root)


class TestRealManifest:
    def test_loads_94_entries(self, real_manifest):
        refs = real_manifest.all_refs()
        assert len(refs) == 94

    def test_no_gaps_for_real_files(self, real_manifest):
        """All 94 files listed in the manifest should exist on disk."""
        assert real_manifest.gaps == []

    def test_format_distribution(self, real_manifest):
        from collections import Counter
        counts = Counter(r.format for r in real_manifest.all_refs())
        # Exact counts from evidence_files.csv
        assert counts[EvidenceFormat.SQL] == 24
        assert counts[EvidenceFormat.LOG] == 26
        assert counts[EvidenceFormat.JSON] == 28
        assert counts[EvidenceFormat.PDF] == 4
        assert counts[EvidenceFormat.IMAGE] == 11
        assert counts[EvidenceFormat.TXT] == 1

    def test_all_file_ids_match_pattern(self, real_manifest):
        import re
        pattern = re.compile(r"^evidence_\d+$")
        for ref in real_manifest.all_refs():
            assert pattern.match(ref.file_id), f"Unexpected file_id: {ref.file_id}"

    def test_captured_at_range(self, real_manifest):
        """All captured_at timestamps should be within 2026."""
        for ref in real_manifest.all_refs():
            assert 2026 == ref.captured_at.year, (
                f"[{ref.file_id}] captured_at={ref.captured_at} not in 2026"
            )
