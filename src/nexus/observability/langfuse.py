"""Langfuse callback handler factory and session helpers.

The factory always returns a duck-typed callback handler so call sites
can attach it unconditionally:

    handler = get_langfuse_handler(session_id)
    await llm.ainvoke(prompt, config={"callbacks": [handler], "metadata": {...}})

When the ``langfuse`` package is not installed *or* the Langfuse
credentials are not configured, ``NullCallbackHandler`` is returned. It
implements the LangChain ``BaseCallbackHandler`` protocol via duck
typing and silently no-ops, which keeps the agents free of conditional
"if handler is None" branches and keeps the unit-test environment from
attempting real network calls.

``flush_langfuse()`` flushes pending events to the Langfuse backend.
The graph runner calls it after each session completes so traces are
not lost on process exit; it is also exposed as ``make langfuse-flush``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

import structlog

from nexus.settings import Settings, get_settings

logger = structlog.get_logger(__name__)


class NullCallbackHandler:
    """Duck-typed no-op callback handler used when Langfuse is unavailable.

    Exposes the subset of LangChain's :class:`BaseCallbackHandler` API
    that agents and ``langchain_openai.ChatOpenAI`` exercise. Every
    method swallows its arguments and returns ``None`` so callers never
    have to branch on handler identity.
    """

    raise_error: bool = False
    ignore_llm: bool = False
    ignore_chain: bool = False
    ignore_agent: bool = False
    ignore_retriever: bool = False
    ignore_chat_model: bool = False

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        """Return a no-op callable for any LangChain callback hook.

        ``on_llm_start``, ``on_chain_end``, ``on_tool_error`` and the rest
        are dispatched dynamically by LangChain; routing every unknown
        attribute through ``_noop`` keeps the surface area resilient to
        new hooks without enumerating every method.
        """
        if name.startswith("on_") or name in {"flush", "shutdown"}:
            return self._noop
        raise AttributeError(name)

    @staticmethod
    def _noop(*_args: Any, **_kwargs: Any) -> None:
        return None


_real_handler_unavailable_logged = False
_client_singleton: Any = None


def get_langfuse_handler(session_id: str) -> Any:  # noqa: ANN401
    """Return a Langfuse callback handler bound to ``session_id``.

    Args:
        session_id: Active pipeline session identifier; surfaces in
            Langfuse as the trace's ``session_id`` and ``trace_name``.

    Returns:
        A LangChain-compatible callback handler. Either the real
        ``langfuse.langchain.CallbackHandler`` when the package is
        installed and credentials are configured, or a
        :class:`NullCallbackHandler` otherwise.
    """
    settings = get_settings()
    if settings.langfuse_public_key is None or settings.langfuse_secret_key is None:
        logger.debug("langfuse_credentials_missing", fallback="NullCallbackHandler")
        return NullCallbackHandler()

    try:
        from langfuse.langchain import CallbackHandler
    except ImportError:
        global _real_handler_unavailable_logged
        if not _real_handler_unavailable_logged:
            logger.warning(
                "langfuse_callback_unavailable",
                reason="langfuse.langchain.CallbackHandler import failed",
                fallback="NullCallbackHandler",
            )
            _real_handler_unavailable_logged = True
        return NullCallbackHandler()

    _ensure_client(settings)
    handler = CallbackHandler()
    # session_id / trace_name surface in Langfuse via attributes the v4
    # handler reads off the active OpenTelemetry span. Stashing them on
    # the handler keeps the agent call sites free of langfuse-specific
    # plumbing.
    handler.session_id = session_id  # type: ignore[attr-defined]
    handler.trace_name = f"nexus/session/{session_id}"  # type: ignore[attr-defined]
    return cast(Any, handler)


def _ensure_client(settings: Settings) -> Any:  # noqa: ANN401
    """Lazily construct (and cache) the module-level Langfuse client."""
    global _client_singleton
    if _client_singleton is not None:
        return _client_singleton
    if settings.langfuse_public_key is None or settings.langfuse_secret_key is None:
        return None
    try:
        from langfuse import Langfuse
    except ImportError:
        return None
    _client_singleton = Langfuse(
        public_key=settings.langfuse_public_key.get_secret_value(),
        secret_key=settings.langfuse_secret_key.get_secret_value(),
        host=settings.langfuse_host,
    )
    return _client_singleton


def flush_langfuse() -> None:
    """Flush pending Langfuse events to the backend.

    Safe to call when Langfuse is not installed or not configured — it
    is a no-op in that case. Invoked by ``make langfuse-flush`` and by
    the graph runner at the end of each session.
    """
    settings = get_settings()
    client = _ensure_client(settings)
    if client is None:
        return
    try:
        client.flush()
    except Exception as exc:  # noqa: BLE001
        # Flushing must never fail a pipeline run.
        logger.warning("langfuse_flush_failed", error=str(exc))


class _NullSpan:
    """No-op span used when Langfuse is unavailable.

    Supports the same surface used by NEXUS agents: enter/exit as a
    context manager plus an ``update(...)`` setter.
    """

    def __enter__(self) -> _NullSpan:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        return None

    def update(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def end(self) -> None:
        return None


@contextmanager
def start_span(
    name: str,
    *,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Iterator[Any]:
    """Yield a Langfuse span (or a no-op span when Langfuse is absent).

    Used by agents that perform non-LLM work (e.g. the Researcher's MCP
    fan-out) so their wall-clock and output appear in the same trace as
    the LLM-driven nodes.
    """
    client = _ensure_client(get_settings())
    if client is None or not hasattr(client, "start_as_current_span"):
        yield _NullSpan()
        return
    try:
        span_cm = client.start_as_current_span(name=name)
    except Exception as exc:  # noqa: BLE001
        logger.warning("langfuse_span_start_failed", name=name, error=str(exc))
        yield _NullSpan()
        return
    try:
        with span_cm as span:
            initial: dict[str, Any] = {}
            if session_id is not None:
                initial["session_id"] = session_id
            if metadata is not None:
                initial["metadata"] = metadata
            if initial:
                try:
                    span.update(**initial)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("langfuse_span_update_failed", error=str(exc))
            yield span
    except Exception as exc:  # noqa: BLE001
        # Honour the same contract as ``_NullSpan``: never let an
        # observability hiccup bubble up into pipeline code.
        logger.warning("langfuse_span_runtime_failed", name=name, error=str(exc))


def reset_langfuse_client_for_tests() -> None:
    """Reset module-level singletons — only used by the test suite."""
    global _client_singleton, _real_handler_unavailable_logged
    _client_singleton = None
    _real_handler_unavailable_logged = False
