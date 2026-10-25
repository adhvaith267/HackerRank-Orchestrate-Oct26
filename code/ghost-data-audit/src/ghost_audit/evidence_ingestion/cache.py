"""
cache.py — Content-addressed extraction cache.

Public API:
    ExtractionCache(cache_dir, extractor_name, extractor_version)
    .get(file_path) -> Optional[List[dict]]   # returns cached facts as plain dicts
    .put(file_path, facts: List[dict]) -> None
    .cache_key(file_path) -> str
    .invalidate(file_path) -> None
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


def _sha256_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def _sha256_str(value: str) -> str:
    """Return the lowercase hex SHA-256 digest of the UTF-8 encoding of *value*."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ExtractionCache:
    """
    Content-addressed cache for evidence extraction results.

    Cache keys are derived from:
      sha256(file_bytes) + ':' + sha256(extractor_name + extractor_version)

    This means the cache is automatically invalidated whenever file content
    or the extractor identity changes, with no explicit TTL needed.

    Cache storage layout::

        cache_dir/
        └── <extractor_name>/
            └── <extractor_version>/
                └── <cache_key>.json
    """

    def __init__(
        self,
        cache_dir: Path,
        extractor_name: str,
        extractor_version: str,
    ) -> None:
        """
        Parameters
        ----------
        cache_dir:
            Root directory for all cache files.
        extractor_name:
            Unique name of the extractor (e.g. ``"sql_extractor"``).
        extractor_version:
            Semantic version or content hash of the extractor
            (e.g. ``"1.0.0"``).
        """
        if not extractor_name:
            raise ValueError("extractor_name must not be empty")
        if not extractor_version:
            raise ValueError("extractor_version must not be empty")

        self._extractor_name = extractor_name
        self._extractor_version = extractor_version
        self._config_hash = _sha256_str(extractor_name + extractor_version)

        # Scoped cache directory: cache_dir / name / version /
        self._store: Path = (
            Path(cache_dir) / extractor_name / extractor_version
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def cache_key(self, file_path: Path | str) -> str:
        """
        Compute and return the cache key for *file_path*.

        The key is ``sha256(file_bytes) + ':' + config_hash`` where
        ``config_hash = sha256(extractor_name + extractor_version)``.

        Returns an empty string if the file cannot be read.
        """
        file_path = Path(file_path)
        try:
            file_bytes = file_path.read_bytes()
        except OSError as exc:
            logger.warning("cache_key: cannot read file (%s): %s", file_path.name, exc)
            return ""
        content_hash = _sha256_bytes(file_bytes)
        return f"{content_hash}:{self._config_hash}"

    def get(self, file_path: Path | str) -> Optional[List[dict]]:
        """
        Return the cached list of fact dicts for *file_path*, or ``None``
        on cache miss or if the entry is malformed.

        Logs a warning on malformed entries but does not raise.
        """
        key = self.cache_key(file_path)
        if not key:
            return None

        cache_file = self._cache_file(key)
        if not cache_file.exists():
            return None

        try:
            raw = cache_file.read_text(encoding="utf-8")
            entry = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "cache.get: malformed cache entry for key %s: %s", key, exc
            )
            return None

        # Validate required fields
        if not isinstance(entry, dict) or "facts" not in entry:
            logger.warning(
                "cache.get: cache entry for key %s is missing 'facts' field", key
            )
            return None

        facts = entry["facts"]
        if not isinstance(facts, list):
            logger.warning(
                "cache.get: 'facts' in cache entry for key %s is not a list", key
            )
            return None

        logger.debug(
            "cache.get: HIT key=%s facts=%d", key, len(facts)
        )
        return facts

    def put(self, file_path: Path | str, facts: List[dict]) -> None:
        """
        Persist *facts* to the cache under the key derived from *file_path*.

        Writes atomically: data is written to a ``.tmp`` file first, then
        renamed to the final path.  Creates parent directories as needed.
        """
        key = self.cache_key(file_path)
        if not key:
            logger.warning("cache.put: skipping — could not compute key for %s", Path(file_path).name)
            return

        entry = {
            "cache_key": key,
            "extractor": self._extractor_name,
            "version": self._extractor_version,
            "cached_at": datetime.now(tz=timezone.utc).isoformat(),
            "facts": facts,
        }

        self._store.mkdir(parents=True, exist_ok=True)
        cache_file = self._cache_file(key)
        tmp_file = cache_file.with_suffix(".tmp")

        try:
            tmp_file.write_text(
                json.dumps(entry, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            os.replace(tmp_file, cache_file)  # atomic on POSIX, best-effort on Windows
        except OSError as exc:
            logger.warning(
                "cache.put: failed to write cache for key %s: %s", key, exc
            )
            # Clean up the temp file if it was left behind
            try:
                tmp_file.unlink(missing_ok=True)
            except OSError:
                pass
            return

        logger.debug("cache.put: STORED key=%s facts=%d", key, len(facts))

    def get_text(self, file_path: Path | str, extractor_version: str) -> Optional[str]:
        """Return cached extracted text, keyed by file content and reader version."""
        key = self._text_key(file_path, extractor_version)
        if not key:
            return None
        cache_file = self._cache_file("text-" + key)
        try:
            entry = json.loads(cache_file.read_text(encoding="utf-8"))
            value = entry.get("text") if isinstance(entry, dict) else None
            return value if isinstance(value, str) else None
        except (OSError, json.JSONDecodeError):
            return None

    def put_text(self, file_path: Path | str, extractor_version: str, text: str) -> None:
        """Atomically cache extracted text without mixing it with fact caches."""
        key = self._text_key(file_path, extractor_version)
        if not key:
            return
        self._store.mkdir(parents=True, exist_ok=True)
        cache_file = self._cache_file("text-" + key)
        tmp_file = cache_file.with_suffix(".tmp")
        entry = {
            "cache_key": key,
            "extractor": self._extractor_name,
            "version": extractor_version,
            "cached_at": datetime.now(tz=timezone.utc).isoformat(),
            "text": text,
        }
        try:
            tmp_file.write_text(json.dumps(entry, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp_file, cache_file)
        except OSError:
            try:
                tmp_file.unlink(missing_ok=True)
            except OSError:
                pass

    def invalidate(self, file_path: Path | str) -> None:
        """
        Remove the cache entry for *file_path*, if any.

        Does nothing if the entry does not exist.
        """
        key = self.cache_key(file_path)
        if not key:
            return

        cache_file = self._cache_file(key)
        try:
            cache_file.unlink(missing_ok=True)
            logger.debug("cache.invalidate: removed key=%s", key)
        except OSError as exc:
            logger.warning(
                "cache.invalidate: failed to remove cache for key %s: %s", key, exc
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _cache_file(self, key: str) -> Path:
        """Return the Path for the cache JSON file for *key*."""
        return self._store / f"{key}.json"

    def _text_key(self, file_path: Path | str, extractor_version: str) -> str:
        file_path = Path(file_path)
        try:
            content_hash = _sha256_bytes(file_path.read_bytes())
        except OSError:
            return ""
        return _sha256_str(content_hash + ":text:" + extractor_version)
