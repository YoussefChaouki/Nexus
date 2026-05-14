"""Tests for ``nexus.graph.graph.run_pipeline``.

The pipeline orchestration is exercised without booting the real
agents: ``build_graph`` is patched to return a stub whose ``ainvoke``
yields a controlled terminal state. This isolates the seeding /
returning behaviour of ``run_pipeline`` from the agents themselves
(those are covered in their own suites).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexus.exceptions import AgentError
from nexus.graph.graph import run_pipeline


def _stub_compiled_with_state(state: dict[str, Any]) -> Any:
    compiled = MagicMock()
    compiled.ainvoke = AsyncMock(return_value=state)
    return compiled


async def test_run_pipeline_returns_report_from_terminal_state(
    sample_threat_report: Callable[..., Any],
) -> None:
    report = sample_threat_report()
    terminal_state = {"threat_report": report}

    with patch(
        "nexus.graph.graph.build_graph",
        return_value=_stub_compiled_with_state(terminal_state),
    ):
        result = await run_pipeline("FastAPI + pgvector RAG, OpenAI, no auth", session_id="s-1")

    assert result is report


async def test_run_pipeline_generates_session_id_when_omitted(
    sample_threat_report: Callable[..., Any],
) -> None:
    report = sample_threat_report()
    stub = _stub_compiled_with_state({"threat_report": report})

    with patch("nexus.graph.graph.build_graph", return_value=stub):
        await run_pipeline("a target architecture description for the pipeline")

    # ``ainvoke`` was given (state, config); the seeded state must carry
    # a non-empty session_id and a corresponding thread_id in config.
    state_arg, config_arg = stub.ainvoke.call_args.args
    assert state_arg["session_id"]
    assert config_arg["configurable"]["thread_id"] == state_arg["session_id"]
    assert state_arg["iteration_count"] == 0
    assert state_arg["should_continue"] is True
    assert state_arg["session_start_time"] > 0


async def test_run_pipeline_raises_when_terminal_state_lacks_report() -> None:
    stub = _stub_compiled_with_state({"threat_report": None})
    with patch("nexus.graph.graph.build_graph", return_value=stub):
        with pytest.raises(AgentError, match="completed without a ThreatReport"):
            await run_pipeline("a target architecture description for the pipeline")
