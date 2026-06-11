"""Abstract base class shared by all NEXUS pipeline agents."""

from abc import ABC, abstractmethod
from typing import Any

import structlog

from nexus.observability.langfuse import get_langfuse_handler
from nexus.schemas.models import AgentState
from nexus.settings import get_settings


class AgentBase(ABC):
    """Common scaffolding for all NEXUS agent nodes."""

    agent_name: str = "base"

    def __init__(self) -> None:
        self._logger = structlog.get_logger(self.__class__.__name__)

    def _get_llm(self) -> Any:  # noqa: ANN401
        """Build a ChatOpenAI instance configured from Settings.

        Returns Any: langchain_openai generics cause mypy module-level type
        contamination when imported at the top of this file, making AgentBase
        appear as Any to subclasses. Lazy import isolates the side-effect.

        Langfuse callbacks are attached at invocation time via
        :meth:`_invoke_config`.
        """
        from langchain_openai import ChatOpenAI  # lazy: keeps module types clean

        settings = get_settings()
        return ChatOpenAI(
            model=settings.llm_model,
            temperature=settings.llm_temperature,
            max_retries=settings.llm_max_retries,
            openai_api_key=settings.openai_api_key.get_secret_value(),
        )

    # ----- Langfuse instrumentation helpers -------------------------------

    def _callbacks(self, state: AgentState) -> list[Any]:
        """Return the callback list to pass to ``llm.ainvoke(config=...)``.

        Always returns a single-element list with either the real Langfuse
        handler or :class:`NullCallbackHandler` — never an empty list — so
        Langfuse instrumentation is uniform across iterations and agents.
        """
        return [get_langfuse_handler(state["session_id"])]

    def _invoke_config(
        self,
        state: AgentState,
        *,
        step: str,
        callbacks: list[Any] | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build the ``config`` kwarg for an instrumented LLM call.

        Standardises the metadata schema (``agent``, ``iteration``,
        ``step``, ``session_id``) so Langfuse traces share a single
        attribute vocabulary across nodes.
        """
        metadata: dict[str, Any] = {
            "agent": self.agent_name,
            "iteration": state["iteration_count"],
            "step": step,
            "session_id": state["session_id"],
        }
        if extra_metadata:
            metadata.update(extra_metadata)
        return {
            "callbacks": callbacks if callbacks is not None else self._callbacks(state),
            "metadata": metadata,
        }

    def _log_start(self, state: AgentState) -> None:
        """Emit a structured entry log at the start of agent execution."""
        self._logger.info(
            "agent_start",
            agent=self.agent_name,
            session_id=state["session_id"],
            iteration=state["iteration_count"],
        )

    @abstractmethod
    async def run(self, state: AgentState) -> AgentState:
        """Execute the agent logic and return an updated state.

        Args:
            state: Current pipeline state (never mutated in place).

        Returns:
            New AgentState dict with modified fields.
        """
        ...
