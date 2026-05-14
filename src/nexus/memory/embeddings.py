"""Shared embedding helper used by agents that query pgvector memory.

The Planner (episodic) and Analyst (semantic) accept an ``embed_fn`` so
unit tests can inject a stub. Production code paths use
:func:`get_openai_embed_fn` so every call site agrees on the embedding
model — matching what ``scripts/ingest_patterns.py`` writes into
``threat_patterns.embedding``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from nexus.exceptions import MemoryLayerError
from nexus.settings import get_settings

logger = structlog.get_logger(__name__)

EmbedFn = Callable[[str], Awaitable[list[float]]]


def get_openai_embed_fn(client: Any | None = None) -> EmbedFn:
    """Return an async ``embed_fn`` backed by the OpenAI embeddings endpoint.

    The function reads :class:`Settings` lazily on every call so test
    suites that patch settings between cases see the updated values.
    When ``client`` is provided it is reused (handy for tests); otherwise
    a fresh :class:`openai.AsyncOpenAI` is constructed per invocation.

    Raises:
        MemoryLayerError: When the embedding request fails — the caller
            (the agent's pattern lookup) downgrades this to a warning so
            the pipeline never aborts on observability/memory hiccups.
    """

    async def _embed(text: str) -> list[float]:
        settings = get_settings()
        oai_client = client
        if oai_client is None:
            from openai import AsyncOpenAI

            oai_client = AsyncOpenAI(api_key=settings.openai_api_key.get_secret_value())
        try:
            response = await oai_client.embeddings.create(
                model=settings.embedding_model,
                input=text,
            )
        except Exception as exc:  # noqa: BLE001
            raise MemoryLayerError(f"embedding request failed: {exc}") from exc
        return list(response.data[0].embedding)

    return _embed
