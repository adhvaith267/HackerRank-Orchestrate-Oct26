"""
config.py — Runtime configuration loader.

Config is read from a YAML file (default: config.yaml, overridable via env var
GHOST_AUDIT_CONFIG).  All paths are resolved relative to the project root.

No secret values belong here — API keys must come from environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Locate project root: the directory containing this file's package root
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).parent  # src/ghost_audit/
_SRC_DIR = _THIS_DIR.parent        # src/
_PROJECT_ROOT = _SRC_DIR.parent    # ghost-data-audit/
# Repo root is two levels above ghost-data-audit/
_REPO_ROOT = _PROJECT_ROOT.parent.parent  # hackerrank-orchestrate-october26/


class DatasetConfig(BaseModel):
    root: Path = Field(
        default=_REPO_ROOT / "dataset",
        description="Absolute path to the dataset/ directory",
    )
    evidence_dir: Path = Field(
        default=_REPO_ROOT / "dataset" / "evidence",
        description="Absolute path to dataset/evidence/",
    )
    deletion_requests: Path = Field(
        default=_REPO_ROOT / "dataset" / "deletion_requests.csv"
    )
    sample_requests: Path = Field(
        default=_REPO_ROOT / "dataset" / "sample_deletion_requests.csv"
    )
    sample_output: Path = Field(
        default=_REPO_ROOT / "dataset" / "sample_output.csv"
    )
    user_identities: Path = Field(
        default=_REPO_ROOT / "dataset" / "user_identities.csv"
    )
    user_audit_log: Path = Field(
        default=_REPO_ROOT / "dataset" / "user_audit_log.csv"
    )
    system_activity: Path = Field(
        default=_REPO_ROOT / "dataset" / "system_activity.csv"
    )
    deletion_rules: Path = Field(
        default=_REPO_ROOT / "dataset" / "deletion_rules.csv"
    )
    evidence_files: Path = Field(
        default=_REPO_ROOT / "dataset" / "evidence_files.csv"
    )

    model_config = {"arbitrary_types_allowed": True}

    @field_validator(
        "root", "evidence_dir", "deletion_requests", "sample_requests",
        "sample_output", "user_identities", "user_audit_log",
        "system_activity", "deletion_rules", "evidence_files",
        mode="before",
    )
    @classmethod
    def _to_path(cls, v: Any) -> Path:
        return Path(v) if not isinstance(v, Path) else v


class OutputConfig(BaseModel):
    output_csv: Path = Field(
        default=_REPO_ROOT / "output.csv",
        description="Absolute path for the final output.csv",
    )
    cache_dir: Path = Field(
        default=_PROJECT_ROOT / ".cache",
        description="Local cache directory for parsed evidence and LLM responses",
    )
    log_path: Path = Field(
        default=_PROJECT_ROOT / "logs" / "final_run.log",
        description="Path for structured run logs",
    )
    manifest_path: Path = Field(
        default=_PROJECT_ROOT / "logs" / "final_run_manifest.json",
    )
    evaluation_dir: Path = Field(
        default=_PROJECT_ROOT / "evaluation",
    )

    model_config = {"arbitrary_types_allowed": True}

    @field_validator(
        "output_csv", "cache_dir", "log_path", "manifest_path", "evaluation_dir",
        mode="before",
    )
    @classmethod
    def _to_path(cls, v: Any) -> Path:
        return Path(v) if not isinstance(v, Path) else v


class LLMConfig(BaseModel):
    mode: str = Field(
        default="off",
        description=(
            "'off' — never call LLM (deterministic rules only), "
            "'auto' — call LLM only for ambiguous cases, "
            "'on' — always call LLM for classification and evidence extraction"
        ),
    )
    provider: str = Field(
        default="ollama",
        description="Local provider identifier; hosted providers are forbidden",
    )
    # Ollama settings
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API base URL",
    )
    ollama_model: str = Field(
        default="qwen2.5:7b",
        description="Ollama model name for text tasks",
    )
    ollama_vision_model: str = Field(
        default="llava",
        description="Ollama model name for image/OCR tasks",
    )
    # Shared settings
    max_evidence_chars: int = Field(
        default=6000,
        description="Maximum characters of evidence text to send per LLM call",
        ge=500,
    )
    request_timeout_seconds: int = Field(default=30, ge=1)
    max_retries: int = Field(default=2, ge=0)
    retry_backoff_base_seconds: float = Field(default=0.5, ge=0.1)
    ollama_num_ctx: int = Field(default=4096, ge=512, le=32768)
    ollama_model_override: Optional[str] = Field(
        default=None,
        description="Optional explicit local model override, e.g. qwen3:8b",
    )
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    enable_ocr: bool = Field(
        default=True,
        description="Whether to run LLM vision on image evidence files",
    )
    enable_pdf_llm: bool = Field(
        default=False,
        description="Whether to send PDF text to LLM (pdftotext is used first)",
    )

    @field_validator("mode")
    @classmethod
    def _valid_mode(cls, v: str) -> str:
        if v not in {"off", "auto", "on"}:
            raise ValueError(f"LLM mode must be 'off', 'auto', or 'on', got {v!r}")
        return v

    @field_validator("provider")
    @classmethod
    def _valid_provider(cls, v: str) -> str:
        if v != "ollama":
            raise ValueError("Only local Ollama is supported; hosted providers are forbidden")
        return v


class RunConfig(BaseModel):
    """Top-level configuration object."""

    dataset: DatasetConfig = Field(default_factory=DatasetConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    max_workers: int = Field(
        default=4,
        description="Thread pool size for parallel case processing",
        ge=1,
    )
    case_limit: Optional[int] = Field(
        default=None,
        description="Process only the first N cases (for development/testing)",
    )
    sample_only: bool = Field(
        default=False,
        description="Run only on sample_deletion_requests.csv",
    )
    verbose: bool = False

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILENAME = "config.yaml"
_ENV_CONFIG_KEY = "GHOST_AUDIT_CONFIG"


def load_config(path: Optional[Path] = None) -> RunConfig:
    """
    Load RunConfig from a YAML file.

    Resolution order:
      1. ``path`` argument
      2. ``GHOST_AUDIT_CONFIG`` environment variable
      3. ``config.yaml`` next to this package's project root
      4. Built-in defaults (no YAML required)
    """
    if path is None:
        env_path = os.environ.get(_ENV_CONFIG_KEY)
        if env_path:
            path = Path(env_path)
        else:
            default = _PROJECT_ROOT / _DEFAULT_CONFIG_FILENAME
            if default.exists():
                path = default

    if path is None or not path.exists():
        return RunConfig()  # all defaults

    with open(path, "r", encoding="utf-8") as fh:
        raw: Dict[str, Any] = yaml.safe_load(fh) or {}

    # A template with comment-only sections (for example ``dataset:``) is
    # parsed by YAML as None. Treat those sections as empty mappings so the
    # documented defaults remain usable after copying config.example.yaml.
    for section in ("dataset", "output", "llm"):
        if raw.get(section) is None:
            raw[section] = {}

    # Nested key resolution: dataset.root, llm.mode, etc.
    return RunConfig.model_validate(raw)
