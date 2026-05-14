"""Tests for ``nexus.settings``."""

from __future__ import annotations

from typing import Any

from pydantic import SecretStr

import nexus.settings as settings_module
from nexus.settings import Settings, get_settings


def test_settings_constructs_with_required_fields(monkeypatch: Any) -> None:
    """With no env vars set, only ``openai_api_key`` is required.

    The autouse ``_test_env`` fixture seeds ``OPENAI_API_KEY`` and the
    Langfuse keys for every other test in the suite; here we want a
    clean environment so the optional-field defaults are observable.
    """
    for key in (
        "ANTHROPIC_API_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
        "LANGFUSE_HOST",
        "NVD_API_KEY",
        "LLM_MODEL",
        "EMBEDDING_MODEL",
        "MAX_ITERATIONS",
    ):
        monkeypatch.delenv(key, raising=False)

    s = Settings(
        openai_api_key=SecretStr("sk-required"),
        _env_file=None,  # type: ignore[call-arg]
    )
    assert s.openai_api_key.get_secret_value() == "sk-required"
    assert s.anthropic_api_key is None
    assert s.langfuse_public_key is None
    assert s.langfuse_secret_key is None
    assert s.llm_model == "gpt-4o"
    assert s.embedding_model == "text-embedding-3-small"
    assert s.max_iterations == 3
    assert s.langfuse_host == "https://cloud.langfuse.com"


def test_settings_accepts_optional_secrets() -> None:
    s = Settings(
        openai_api_key=SecretStr("sk"),
        anthropic_api_key=SecretStr("ant"),
        langfuse_public_key=SecretStr("pk"),
        langfuse_secret_key=SecretStr("sk-lf"),
        nvd_api_key=SecretStr("nvd"),
    )
    assert s.anthropic_api_key is not None
    assert s.nvd_api_key is not None
    assert s.langfuse_public_key is not None


def test_get_settings_caches_instance() -> None:
    settings_module._settings = None
    first = get_settings()
    second = get_settings()
    assert first is second
