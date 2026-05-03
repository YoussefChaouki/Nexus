"""Abstract base class shared by all NEXUS pipeline agents."""

from abc import ABC, abstractmethod
from typing import Any

import structlog

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

        Langfuse callbacks are attached at invocation time via:
            llm.ainvoke(messages, config={"callbacks": [get_langfuse_handler(session_id)]})
        """
        from langchain_openai import ChatOpenAI  # lazy: keeps module types clean

        settings = get_settings()
        return ChatOpenAI(
            model=settings.llm_model,
            openai_api_key=settings.openai_api_key.get_secret_value(),
        )

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
