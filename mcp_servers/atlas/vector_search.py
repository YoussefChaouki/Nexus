"""In-memory cosine-similarity search over MITRE ATLAS techniques.

The full-pgvector index is intentionally avoided here — the ATLAS corpus
is small (low hundreds of techniques), so a NumPy matrix multiplication
is plenty fast and avoids pulling Postgres into this MCP server's
dependency tree. Embeddings are computed once at startup with
``text-embedding-3-small`` (overridable via the ``embed_fn`` constructor
argument so tests can inject deterministic vectors).
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Final

import numpy as np
import structlog
from schemas import ATLASTechnique

logger = structlog.get_logger(__name__)

EmbedFn = Callable[[list[str]], Awaitable[list[list[float]]]]

DEFAULT_EMBED_MODEL: Final[str] = "text-embedding-3-small"
DEFAULT_EMBED_DIM: Final[int] = 1536


def _technique_text(t: ATLASTechnique) -> str:
    """Pack the searchable surface of a technique into one string."""
    return f"{t.name}. {t.description} Tactic: {t.tactic}".strip()


async def default_openai_embed(texts: list[str]) -> list[list[float]]:
    """Embed ``texts`` with OpenAI's ``text-embedding-3-small`` model.

    The OpenAI client is imported lazily so that callers who inject a
    custom ``embed_fn`` (e.g. tests) never have to install ``openai``.
    """
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    response = await client.embeddings.create(model=DEFAULT_EMBED_MODEL, input=texts)
    return [item.embedding for item in response.data]


class ATLASVectorSearch:
    """Cosine-similarity search over a static ATLAS corpus."""

    def __init__(
        self,
        techniques: list[ATLASTechnique],
        embed_fn: EmbedFn | None = None,
    ) -> None:
        self._techniques = list(techniques)
        self._embed_fn: EmbedFn = embed_fn or default_openai_embed
        self._matrix: np.ndarray | None = None  # shape (N, D), L2-normalised
        self._techniques_by_id: dict[str, ATLASTechnique] = {
            t.technique_id: t for t in self._techniques
        }

    @property
    def is_indexed(self) -> bool:
        return self._matrix is not None

    @property
    def techniques(self) -> list[ATLASTechnique]:
        return list(self._techniques)

    def get_by_id(self, technique_id: str) -> ATLASTechnique | None:
        return self._techniques_by_id.get(technique_id)

    def filter_by_tactic(self, tactic_name: str) -> list[ATLASTechnique]:
        needle = tactic_name.strip().lower()
        return [
            t
            for t in self._techniques
            if any(part.strip().lower() == needle for part in t.tactic.split(","))
        ]

    async def build_index(self) -> None:
        """Compute embeddings for every technique. Idempotent."""
        if self._matrix is not None or not self._techniques:
            return
        texts = [_technique_text(t) for t in self._techniques]
        raw = await self._embed_fn(texts)
        matrix = np.asarray(raw, dtype=np.float32)
        if matrix.ndim != 2 or matrix.shape[0] != len(self._techniques):
            raise ValueError(
                "embed_fn returned a malformed matrix: "
                f"shape={matrix.shape}, expected=({len(self._techniques)}, D)",
            )
        self._matrix = _l2_normalise(matrix)

    async def search(self, query: str, limit: int = 10) -> list[ATLASTechnique]:
        """Return up to ``limit`` techniques ranked by cosine similarity."""
        if not self._techniques:
            return []
        if self._matrix is None:
            await self.build_index()
        assert self._matrix is not None  # narrowed for mypy

        query_vecs = await self._embed_fn([query])
        query_vec = np.asarray(query_vecs[0], dtype=np.float32)
        if query_vec.shape != (self._matrix.shape[1],):
            raise ValueError(
                f"query embedding dim {query_vec.shape} does not match index "
                f"dim ({self._matrix.shape[1]},)",
            )
        query_vec = _l2_normalise(query_vec[None, :])[0]

        scores = self._matrix @ query_vec
        top_count = min(limit, scores.shape[0])
        # argpartition is O(N) for the top-k; we sort just the slice.
        partition = np.argpartition(-scores, top_count - 1)[:top_count]
        ranked = partition[np.argsort(-scores[partition])]
        return [self._techniques[int(i)] for i in ranked]


def _l2_normalise(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    result: np.ndarray = matrix / norms
    return result
