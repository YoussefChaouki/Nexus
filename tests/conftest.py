"""Shared pytest fixtures for the NEXUS test suite."""

import os
from collections.abc import Generator

import pytest


@pytest.fixture(autouse=True, scope="session")
def _test_env() -> Generator[None, None, None]:
    """Set minimum required env vars so Settings() can be instantiated in tests."""
    os.environ.setdefault("OPENAI_API_KEY", "sk-test-00000000000000000000000000000000")
    os.environ.setdefault("LANGFUSE_PUBLIC_KEY", "pk-lf-test")
    os.environ.setdefault("LANGFUSE_SECRET_KEY", "sk-lf-test")

    import nexus.settings as _mod

    _mod._settings = None  # reset module-level cache so tests pick up env vars
    yield
