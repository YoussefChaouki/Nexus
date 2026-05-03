"""Langfuse callback handler factory."""

from typing import cast

import structlog
from langchain_core.callbacks import BaseCallbackHandler

logger = structlog.get_logger(__name__)


def get_langfuse_handler(session_id: str) -> BaseCallbackHandler | None:
    """Return a Langfuse CallbackHandler, or None when the package is missing.

    Args:
        session_id: Active pipeline session identifier.

    Returns:
        Configured Langfuse handler, or None if langfuse is not installed.
    """
    try:
        from langfuse.callback import CallbackHandler
    except ImportError:
        logger.warning("langfuse_unavailable", reason="langfuse package not installed")
        return None

    from nexus.settings import get_settings

    settings = get_settings()
    return cast(
        BaseCallbackHandler,
        CallbackHandler(
            public_key=settings.langfuse_public_key.get_secret_value(),
            secret_key=settings.langfuse_secret_key.get_secret_value(),
            host=settings.langfuse_host,
            session_id=session_id,
            trace_name=f"nexus/session/{session_id}",
        ),
    )
