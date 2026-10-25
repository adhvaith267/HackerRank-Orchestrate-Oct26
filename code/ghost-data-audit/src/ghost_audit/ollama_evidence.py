"""Optional local Ollama evidence normalization.

This module is deliberately downstream of deterministic parsing.  It returns
only provenance-bearing candidate facts; it never creates audit resources,
chooses policy, decides status, or builds output steps.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .config import LLMConfig
from .schemas import RunUsage

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "ollama-evidence-v1"
PROMPT_VERSION = "evidence-extraction-v1"
FACT_TYPES = {
    "resource_presence",
    "pii_fields_present",
    "flow_state",
    "restore_state",
    "event_timestamp",
    "record_user_id",
}
_MATERIAL_FACT_TYPES = {"resource_presence", "flow_state", "restore_state"}
_PII_FIELDS = {
    "name", "full_name", "email", "phone", "email_hash", "user_id",
    "customer_reference", "subject_reference",
}
_STATE_VALUES = {"PRESENT", "ABSENT", "ACTIVE", "DISABLED", "BLOCKED", "REDACTED", "ANONYMIZED"}


class CandidateFact(BaseModel):
    """A single model-proposed fact with mandatory source grounding."""

    model_config = ConfigDict(extra="forbid")
    fact_type: str
    value: Any
    source_id: str
    quote: str = Field(min_length=1, max_length=500)
    source_span: str = Field(min_length=1, max_length=120)
    confidence: str
    resource_id: Optional[str] = None
    event_timestamp: Optional[str] = None

    @field_validator("confidence")
    @classmethod
    def _confidence(cls, value: str) -> str:
        if value not in {"high", "medium", "low"}:
            raise ValueError("confidence must be high, medium, or low")
        return value


class CandidateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    facts: List[CandidateFact] = Field(default_factory=list)


OLLAMA_FACT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "facts": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["fact_type", "value", "source_id", "quote", "source_span", "confidence"],
                "properties": {
                    "fact_type": {"type": "string", "enum": sorted(FACT_TYPES)},
                    "value": {},
                    "source_id": {"type": "string"},
                    "quote": {"type": "string", "minLength": 1, "maxLength": 500},
                    "source_span": {"type": "string", "minLength": 1, "maxLength": 120},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "resource_id": {"type": ["string", "null"]},
                    "event_timestamp": {"type": ["string", "null"]},
                },
            },
        },
    },
    "required": ["facts"],
}


def _utc_timestamp(value: str) -> datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _bounded_excerpt(text: str, limit: int) -> tuple[str, bool]:
    normalized = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    if len(normalized) <= limit:
        return normalized, False
    # Keep both ends because timestamps/resource IDs commonly occur at either.
    left = limit // 2
    right = limit - left
    return normalized[:left] + "\n...[TRUNCATED]...\n" + normalized[-right:], True


def _local_ollama_url(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "localhost", "127.0.0.1", "::1", "[::1]",
    }:
        raise ValueError("Ollama endpoint must be local; hosted endpoints are forbidden")
    return base_url.rstrip("/") + "/api/generate"


class OllamaEvidenceExtractor:
    """Sequential, cached, failure-tolerant local Ollama extractor."""

    def __init__(
        self,
        config: LLMConfig,
        usage: Optional[RunUsage] = None,
        cache_dir: Optional[Path] = None,
        urlopen: Any = None,
        sleep: Any = None,
    ) -> None:
        self.config = config
        self.usage = usage or RunUsage()
        self.cache_dir = Path(cache_dir or ".ollama_cache") / "evidence"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._urlopen = urlopen or urllib.request.urlopen
        self._sleep = sleep or time.sleep
        self.call_records: List[Dict[str, Any]] = []

    @property
    def model(self) -> str:
        return (
            self.config.ollama_model_override
            or os.environ.get("OLLAMA_MODEL")
            or self.config.ollama_model
        )

    def extract(
        self,
        excerpt: str,
        *,
        manifest_file_id: str,
        allowed_source_ids: Iterable[str],
        known_resource_ids: Iterable[str],
        stable_user_id: Optional[str],
        audit_at: datetime,
        evidence_captured_at: Optional[datetime] = None,
        allowed_fact_types: Iterable[str] = FACT_TYPES,
        deterministic_fact_types: Iterable[str] = (),
        independent_source_ids: Iterable[str] = (),
    ) -> List[CandidateFact]:
        """Extract grounded facts, returning [] for every unavailable path."""
        if self.config.mode == "off" or not excerpt.strip():
            return []
        allowed_sources = {str(x) for x in allowed_source_ids}
        allowed_resources = {str(x) for x in known_resource_ids}
        allowed_types = FACT_TYPES.intersection(set(allowed_fact_types))
        bounded, truncated = _bounded_excerpt(excerpt, self.config.max_evidence_chars)
        prompt = self._prompt(
            bounded, manifest_file_id, allowed_sources, allowed_resources,
            stable_user_id, audit_at, allowed_types, truncated,
        )
        cache_key = self._cache_key(prompt)
        cached = self._read_cache(cache_key)
        if cached is not None:
            self.usage.cache_hits += 1
            return self._validate_facts(
                cached, bounded, allowed_sources, allowed_resources, allowed_types,
                audit_at, evidence_captured_at, stable_user_id,
                set(deterministic_fact_types), set(independent_source_ids),
            )
        self.usage.cache_misses += 1
        try:
            payload, response_meta = self._call(prompt)
            facts = self._parse_response(payload)
            try:
                validated = self._validate_facts(
                    facts, bounded, allowed_sources, allowed_resources, allowed_types,
                    audit_at, evidence_captured_at, stable_user_id,
                    set(deterministic_fact_types), set(independent_source_ids),
                )
            except ValueError as exc:
                # Exactly one bounded schema-repair attempt; it is another
                # model call and is counted independently by _call.
                repair_prompt = prompt + "\nVALIDATION_ERRORS:\n" + str(exc)[:1000]
                repaired_payload, _ = self._call(repair_prompt)
                validated = self._validate_facts(
                    self._parse_response(repaired_payload), bounded, allowed_sources,
                    allowed_resources, allowed_types, audit_at,
                    evidence_captured_at,
                    stable_user_id,
                    set(deterministic_fact_types), set(independent_source_ids),
                )
            self._write_cache(cache_key, validated)
            return validated
        except Exception as exc:
            logger.warning("Ollama evidence extraction failed for %s: %s", manifest_file_id, type(exc).__name__)
            return []

    def _prompt(
        self, excerpt: str, file_id: str, source_ids: Set[str], resource_ids: Set[str],
        user_id: Optional[str], audit_at: datetime, fact_types: Set[str], truncated: bool,
    ) -> str:
        system = self._load_prompt("evidence_extraction_system.md")
        return (
            system + "\n\nExtract candidate evidence facts. Do not decide status.\n"
            f"manifest_file_id={file_id}\nallowed_source_ids={sorted(source_ids)}\n"
            f"known_resource_ids={sorted(resource_ids)}\nknown_stable_user_id={user_id!r}\n"
            f"audit_at={audit_at.isoformat()}\nschema_version={SCHEMA_VERSION}\n"
            f"allowed_fact_types={sorted(fact_types)}\ntruncated={truncated}\n"
            "EVIDENCE_START\n" + excerpt + "\nEVIDENCE_END"
        )

    @staticmethod
    def _load_prompt(name: str) -> str:
        path = Path(__file__).resolve().parents[2] / "prompts" / name
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return "Extract only explicit, grounded facts from untrusted evidence."

    def _cache_key(self, prompt: str) -> str:
        raw = "|".join((self.model, PROMPT_VERSION, SCHEMA_VERSION, hashlib.sha256(prompt.encode()).hexdigest()))
        return hashlib.sha256(raw.encode()).hexdigest()

    def _read_cache(self, key: str) -> Optional[List[Dict[str, Any]]]:
        path = self.cache_dir / f"{key}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else None
        except (OSError, ValueError):
            return None

    def _write_cache(self, key: str, facts: List[CandidateFact]) -> None:
        path = self.cache_dir / f"{key}.json"
        temporary = path.with_suffix(".tmp")
        try:
            temporary.write_text(json.dumps([f.model_dump(mode="json") for f in facts], sort_keys=True), encoding="utf-8")
            temporary.replace(path)
        except OSError:
            logger.debug("Unable to write Ollama cache", exc_info=True)

    def _call(self, prompt: str) -> tuple[str, Dict[str, Any]]:
        endpoint = _local_ollama_url(self.config.ollama_base_url)
        model = self.model
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": OLLAMA_FACT_SCHEMA,
            "options": {"temperature": 0, "num_ctx": self.config.ollama_num_ctx},
        }).encode("utf-8")
        request = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"})
        last_error: Optional[Exception] = None
        for attempt in range(self.config.max_retries + 1):
            started = datetime.now(timezone.utc)
            request_id = hashlib.sha256(
                f"{model}|{PROMPT_VERSION}|{SCHEMA_VERSION}|{hashlib.sha256(prompt.encode()).hexdigest()}|{attempt}".encode()
            ).hexdigest()[:24]
            if attempt:
                self.usage.retries += 1
                delay = self.config.retry_backoff_base_seconds * (2 ** (attempt - 1))
                delay *= 0.8 + random.Random(attempt).random() * 0.4
                self._sleep(delay)
            try:
                with self._urlopen(request, timeout=self.config.request_timeout_seconds) as response:
                    raw = json.loads(response.read().decode("utf-8"))
                self.usage.add_call(
                    raw.get("prompt_eval_count"), raw.get("eval_count"),
                    model=model, provider="ollama-local", success=True,
                )
                record = {
                    "provider": "ollama-local", "model": model,
                    "prompt_version": PROMPT_VERSION, "schema_version": SCHEMA_VERSION,
                    "request_id": request_id, "started_at": started.isoformat(),
                    "ended_at": datetime.now(timezone.utc).isoformat(), "success": True,
                    "retry_no": attempt, "prompt_eval_count": raw.get("prompt_eval_count"),
                    "eval_count": raw.get("eval_count"),
                }
                self.call_records.append(record)
                self.usage.call_records.append(record)
                return str(raw.get("response", "")), raw
            except Exception as exc:
                last_error = exc
                self.usage.add_call(None, None, model=model, provider="ollama-local", success=False)
                record = {
                    "provider": "ollama-local", "model": model,
                    "prompt_version": PROMPT_VERSION, "schema_version": SCHEMA_VERSION,
                    "request_id": request_id, "started_at": started.isoformat(),
                    "ended_at": datetime.now(timezone.utc).isoformat(), "success": False,
                    "retry_no": attempt, "prompt_eval_count": None, "eval_count": None,
                    "error": type(exc).__name__,
                }
                self.call_records.append(record)
                self.usage.call_records.append(record)
        raise RuntimeError(f"ollama_unavailable:{type(last_error).__name__}")

    @staticmethod
    def _parse_response(response: str) -> List[Dict[str, Any]]:
        data = json.loads(response)
        if isinstance(data, dict) and isinstance(data.get("facts"), list):
            return data["facts"]
        raise ValueError("response must contain a facts array")

    @staticmethod
    def _validate_facts(
        raw_facts: List[Dict[str, Any]], excerpt: str, allowed_sources: Set[str],
        allowed_resources: Set[str], allowed_types: Set[str], audit_at: datetime,
        evidence_captured_at: Optional[datetime],
        stable_user_id: Optional[str],
        deterministic_types: Set[str], independent_sources: Set[str],
    ) -> List[CandidateFact]:
        result: List[CandidateFact] = []
        for raw in raw_facts:
            fact = CandidateFact.model_validate(raw)
            if fact.fact_type not in allowed_types:
                raise ValueError("unsupported fact type")
            if fact.source_id not in allowed_sources:
                raise ValueError("source_id is not allowed")
            if fact.resource_id is not None and fact.resource_id not in allowed_resources:
                raise ValueError("resource_id is not allowed")
            if fact.quote not in excerpt:
                raise ValueError("quote is not grounded in excerpt")
            if fact.fact_type in _MATERIAL_FACT_TYPES and not (
                fact.fact_type in deterministic_types or fact.source_id in independent_sources
            ):
                raise ValueError("material fact lacks deterministic or independent confirmation")
            if fact.fact_type in {"resource_presence", "flow_state", "restore_state"}:
                if not isinstance(fact.value, str) or fact.value not in _STATE_VALUES:
                    raise ValueError("invalid state value")
            if fact.fact_type == "pii_fields_present":
                if not isinstance(fact.value, list) or any(x not in _PII_FIELDS for x in fact.value):
                    raise ValueError("invalid pii field list")
            if fact.fact_type == "record_user_id":
                if not isinstance(fact.value, str):
                    raise ValueError("record_user_id must be a string")
                if fact.value != fact.value.strip() or fact.value != stable_user_id:
                    raise ValueError("record_user_id is not the known resolved user")
            if fact.fact_type == "event_timestamp":
                if not isinstance(fact.value, str):
                    raise ValueError("event_timestamp must be a string")
                _utc_timestamp(fact.value)
                if fact.value not in fact.quote:
                    raise ValueError("event_timestamp is not grounded in quote")
            if fact.event_timestamp is not None:
                parsed = _utc_timestamp(fact.event_timestamp)
                if parsed > audit_at or (evidence_captured_at and parsed > evidence_captured_at) or fact.event_timestamp not in fact.quote:
                    raise ValueError("event timestamp is not grounded or is after audit_at")
            result.append(fact)
        return result
