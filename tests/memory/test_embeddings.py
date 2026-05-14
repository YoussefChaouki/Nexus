"""Tests for the shared ``get_openai_embed_fn`` helper."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from nexus.exceptions import MemoryLayerError
from nexus.memory.embeddings import get_openai_embed_fn


def _client_returning(vector: list[float]) -> MagicMock:
    client = MagicMock()
    client.embeddings = MagicMock()
    client.embeddings.create = AsyncMock(
        return_value=MagicMock(data=[MagicMock(embedding=vector)]),
    )
    return client


async def test_get_openai_embed_fn_uses_configured_model() -> None:
    client = _client_returning([0.1, 0.2, 0.3])
    embed = get_openai_embed_fn(client=client)

    result = await embed("anything")

    assert result == [0.1, 0.2, 0.3]
    kwargs = client.embeddings.create.call_args.kwargs
    # Must agree with the model used by scripts/ingest_patterns.py so
    # query and index vectors live in the same embedding space.
    assert kwargs["model"] == "text-embedding-3-small"
    assert kwargs["input"] == "anything"


async def test_get_openai_embed_fn_wraps_errors_as_memory_layer_error() -> None:
    client = MagicMock()
    client.embeddings = MagicMock()
    client.embeddings.create = AsyncMock(side_effect=RuntimeError("boom"))
    embed = get_openai_embed_fn(client=client)

    with pytest.raises(MemoryLayerError, match="embedding request failed"):
        await embed("payload")
