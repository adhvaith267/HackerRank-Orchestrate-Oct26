"""
llm.py — LLM client abstraction.

Provides:
  LLMClient(config: LLMConfig)
    .classify_request(request_text, case_id) -> RequestClassification
    .extract_image_facts(ref, path, resolution, all_ids) -> List[EvidenceFact]

LLM mode:
  'off'  — all calls return deterministic defaults (no network calls)
  'auto' — call LLM only for ambiguous cases
  'on'   — always call LLM

No API keys are read by this module. Ollama is local-only.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, ConfigDict, StrictBool, ValidationError

from .config import LLMConfig
from .schemas import (
    DataCategory,
    EvidenceFact,
    EvidenceRef,
    LLMConfidence,
    RecordState,
    RunUsage,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Request classification result
# ---------------------------------------------------------------------------

class RequestClassification:
    """Result of classifying a request_text for deletion authorization."""

    def __init__(
        self,
        authorized: bool,
        reason: str,
        confidence: LLMConfidence,
        method: str = "rules",  # 'rules', 'llm'
    ) -> None:
        self.authorized = authorized
        self.reason = reason
        self.confidence = confidence
        self.method = method


class _ClassificationResponse(BaseModel):
    """Strict parser for legacy classification responses.

    The production path does not ask a model to authorize deletion, but this
    parser remains defensive for direct callers and regression tests.
    """

    model_config = ConfigDict(extra="forbid")
    authorized: StrictBool
    reason: str
    confidence: str


# ---------------------------------------------------------------------------
# Keyword-based classifier (no LLM required)
# ---------------------------------------------------------------------------

# Phrases that clearly authorize deletion (multilingual, from sample cases)
_DELETION_PHRASES = [
    "delete", "deletion", "erase", "erased", "remove", "removal", "close my account",
    "closing my account", "account closure", "permanent deletion", "permanently delete",
    "suppression", "supprimer", "supprimez", "effacement", "supresión", "eliminar",
    "eliminación", "borrar", "elimina", "削除", "アカウントを削除", "退会", "消去",
    "gdpr", "right to erasure", "right to be forgotten",
    "account deletion", "delete my account", "personal data deletion",
    "please remove", "wipe my data", "data erasure", "close account",
    "permanently remove",
]

# Phrases that signal non-deletion requests (access, export, correction, opt-out)
_NON_DELETION_PHRASES = [
    "download a copy", "access my data", "export my data", "download my data",
    "copy of my data", "data portability", "correct my", "update my", "change my",
    "opt out", "opt-out", "unsubscribe", "marketing", "newsletter",
    "what data do you have", "data inquiry", "right to access",
    "download all my data", "provide me with",
]


def _classify_by_rules(request_text: str) -> Optional[RequestClassification]:
    """
    Attempt rule-based classification.
    Returns None if the text is ambiguous (needs LLM).
    """
    text_lower = request_text.lower()

    non_del_hits = [p for p in _NON_DELETION_PHRASES if p in text_lower]
    del_hits = [p for p in _DELETION_PHRASES if p in text_lower]

    # Clear non-deletion: non-deletion keywords present, no deletion keywords
    if non_del_hits and not del_hits:
        return RequestClassification(
            authorized=False,
            reason=f"Request contains non-deletion keywords: {non_del_hits[:3]}",
            confidence=LLMConfidence.HIGH,
            method="rules",
        )

    # Clear deletion
    if del_hits:
        return RequestClassification(
            authorized=True,
            reason=f"Request contains deletion keywords: {del_hits[:3]}",
            confidence=LLMConfidence.HIGH,
            method="rules",
        )

    return None  # Ambiguous — escalate to LLM


# ---------------------------------------------------------------------------
# LLM Client
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Thin wrapper around LLM providers for deletion audit tasks.
  Supports local Ollama only. Hosted APIs are intentionally forbidden.
    """

    def __init__(self, config: LLMConfig, usage: Optional[RunUsage] = None) -> None:
        self._config = config
        self._usage = usage or RunUsage()

    # ------------------------------------------------------------------
    # Request classification
    # ------------------------------------------------------------------

    def classify_request(
        self, request_text: str, case_id: str = ""
    ) -> RequestClassification:
        """
        Classify request_text: does it authorize deletion?

        Always tries rule-based first. Falls back to LLM if mode != 'off'
        and the text is ambiguous.
        """
        # Try rules first
        rule_result = _classify_by_rules(request_text)
        if rule_result is not None:
            return rule_result

        # Authorization is a status-adjacent decision and is deliberately
        # deterministic.  Ambiguous text never becomes an authorized
        # deletion through a model call.
        return RequestClassification(
            authorized=False,
            reason="Ambiguous request; no explicit deletion authorization established",
            confidence=LLMConfidence.LOW,
            method="rules_fallback",
        )

    def _llm_classify(
        self, request_text: str, case_id: str
    ) -> RequestClassification:
        prompt = _CLASSIFY_PROMPT.format(
            request_text=request_text[:self._config.max_evidence_chars]
        )
        try:
            response = self._call_text(prompt)
            return self._parse_classify_response(response)
        except Exception as exc:
            logger.warning("[%s] LLM classification failed: %s", case_id, exc)
            return RequestClassification(
                authorized=False,
                reason=f"LLM call failed ({type(exc).__name__}); no deletion authorization established",
                confidence=LLMConfidence.LOW,
                method="llm_error",
            )

    @staticmethod
    def _parse_classify_response(response: str) -> RequestClassification:
        """Parse JSON response from the LLM classifier."""
        try:
            parsed = _ClassificationResponse.model_validate(json.loads(response))
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            raise ValueError("invalid structured classification response") from exc
        if parsed.confidence not in {"high", "medium", "low"}:
            raise ValueError("invalid classification confidence")
        conf = LLMConfidence(parsed.confidence)
        return RequestClassification(
            authorized=parsed.authorized,
            reason=parsed.reason,
            confidence=conf,
            method="llm",
        )

    # ------------------------------------------------------------------
    # Image fact extraction
    # ------------------------------------------------------------------

    def extract_image_facts(
        self,
        ref: EvidenceRef,
        path: Path,
        resolution: Any,  # IdentityResolution — avoid circular import
        all_ids: Set[str],
    ) -> List[EvidenceFact]:
        """Extract EvidenceFacts from a screenshot using LLM vision."""
        if self._config.mode == "off":
            return []

        try:
            image_b64 = base64.b64encode(path.read_bytes()).decode()
        except Exception as exc:
            logger.warning("Image read error %s: %s", path, exc)
            return []

        prompt = _IMAGE_PROMPT.format(
            identifiers=", ".join(list(all_ids)[:10])
        )
        try:
            response = self._call_vision(prompt, image_b64)
            return self._parse_image_response(response, ref, resolution)
        except Exception as exc:
            logger.warning("Image LLM call failed for %s: %s", ref.file_id, exc)
            return []

    def _parse_image_response(
        self, response: str, ref: EvidenceRef, resolution: Any
    ) -> List[EvidenceFact]:
        """Parse JSON array of facts from image LLM response."""
        facts: List[EvidenceFact] = []
        try:
            data = json.loads(response)
            items = data if isinstance(data, list) else data.get("facts", [])
        except Exception:
            return []

        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                state_str = item.get("state", "PRESENT")
                state = RecordState(state_str) if state_str in RecordState._value2member_map_ else RecordState.PRESENT
                cat_str = item.get("data_category", "USER_PROFILE")
                try:
                    cat = DataCategory(cat_str)
                except ValueError:
                    cat = DataCategory.USER_PROFILE
                facts.append(EvidenceFact(
                    file_id=ref.file_id,
                    file_path=ref.file_path,
                    captured_at=ref.captured_at,
                    system_id=item.get("system_id", ""),
                    resource_id=item.get("resource_id", ""),
                    subject_user_id=resolution.user_id,
                    subject_email=resolution.input_email,
                    data_category=cat,
                    observed_state=state,
                    raw_value=json.dumps(item)[:self._config.max_evidence_chars],
                    source_span="image:llm",
                    llm_derived=True,
                    llm_confidence=LLMConfidence.MEDIUM,
                ))
            except Exception as exc:
                logger.debug("Image fact parse error: %s", exc)
        return facts

    # ------------------------------------------------------------------
    # Low-level API calls
    # ------------------------------------------------------------------

    def _call_text(self, prompt: str) -> str:
        """Call the configured LLM provider with a text prompt."""
        if self._config.provider == "ollama":
            return self._call_ollama(prompt, model=self._config.ollama_model)
        raise NotImplementedError("Only local Ollama is supported")

    def _call_vision(self, prompt: str, image_b64: str) -> str:
        """Call the configured LLM provider with an image."""
        if self._config.provider == "ollama":
            return self._call_ollama_vision(prompt, image_b64)
        raise NotImplementedError("Only local Ollama is supported")

    def _call_ollama(self, prompt: str, model: Optional[str] = None) -> str:
        import urllib.request
        model = model or self._config.ollama_model
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self._config.temperature},
        }).encode()
        url = f"{self._config.ollama_base_url}/api/generate"
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        for attempt in range(self._config.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self._config.request_timeout_seconds) as resp:
                    data = json.loads(resp.read())
                    response_text = data.get("response", "")
                    self._usage.add_call(
                        input_toks=data.get("prompt_eval_count"),
                        output_toks=data.get("eval_count"),
                        model=model,
                        provider="ollama-local",
                        success=True,
                    )
                    return response_text
            except Exception as exc:
                self._usage.add_call(
                    input_toks=None,
                    output_toks=None,
                    model=model,
                    provider="ollama-local",
                    success=False,
                )
                if attempt < self._config.max_retries:
                    wait = self._config.retry_backoff_base_seconds * (2 ** attempt)
                    logger.debug("Ollama retry %d after %.1fs: %s", attempt + 1, wait, exc)
                    time.sleep(wait)
                else:
                    raise

    def _call_ollama_vision(self, prompt: str, image_b64: str) -> str:
        import urllib.request
        model = self._config.ollama_vision_model
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "images": [image_b64],
            "stream": False,
        }).encode()
        url = f"{self._config.ollama_base_url}/api/generate"
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self._config.request_timeout_seconds) as resp:
            data = json.loads(resp.read())
            self._usage.add_call(
                input_toks=data.get("prompt_eval_count"),
                output_toks=data.get("eval_count"),
                model=model,
                provider="ollama-local",
                success=True,
            )
            return data.get("response", "")

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_CLASSIFY_PROMPT = """You are a privacy compliance analyst reviewing a data deletion request.

Determine whether the following message authorizes a deletion of personal data.
A request is authorized if the user is asking to:
- delete their account or personal data
- erase or remove their profile, history, or records
- exercise their right to erasure / right to be forgotten

A request is NOT authorized if the user is asking to:
- access, download, or export their data
- correct or update their data
- opt out of marketing only
- submit a general inquiry or complaint

Respond with a JSON object only, no prose:
{{"authorized": true/false, "reason": "brief explanation", "confidence": "high/medium/low"}}

Request text:
{request_text}
"""

_IMAGE_PROMPT = """You are a privacy auditor examining a screenshot from an internal system.

The subject has the following identifiers: {identifiers}

Extract any records visible in the screenshot that belong to this subject.
For each record found, determine:
- system_id (e.g. account_service, search_service, analytics_platform, support_platform,
  export_service, integration_service, backup_service, security_service,
  identity_service, marketing_platform)
- resource_id (the unique record ID visible in the screenshot)
- state: PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, or BLOCKED
- data_category: one of USER_PROFILE, SEARCH_INDEX_ENTRY, ANALYTICS_PROFILE,
  SUPPORT_MESSAGE, USER_EXPORT, BACKUP_ARCHIVE, SECURITY_AUDIT_LOG,
  ACCOUNT_TOMBSTONE, MARKETING_PROFILE

Respond with a JSON array only:
[{{"system_id":"...","resource_id":"...","state":"...","data_category":"..."}}]

If no matching records are found, respond with: []
"""
