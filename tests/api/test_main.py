"""Tests for the NEXUS FastAPI app.

Every test builds a fresh app via :func:`create_app` and overrides the
dependency providers so no real Redis / Postgres / pipeline runs.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from nexus.api.main import (
    create_app,
    get_pg_pool,
    get_pipeline_runner,
    get_pipeline_streamer,
    get_redis,
)
from nexus.exceptions import AgentError
from nexus.schemas.models import AgentEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_client(
    *,
    runner: Any = None,
    streamer: Any = None,
    redis_client: Any = None,
    pg_pool: Any = None,
) -> TestClient:
    """Build a TestClient with the given dependency overrides."""
    app = create_app()
    if runner is not None:
        app.dependency_overrides[get_pipeline_runner] = lambda: runner
    if streamer is not None:
        app.dependency_overrides[get_pipeline_streamer] = lambda: streamer
    app.dependency_overrides[get_redis] = lambda: redis_client
    app.dependency_overrides[get_pg_pool] = lambda: pg_pool
    return TestClient(app)


# ---------------------------------------------------------------------------
# POST /analyze
# ---------------------------------------------------------------------------


def test_post_analyze_returns_report(
    sample_threat_report: Callable[..., Any],
) -> None:
    report = sample_threat_report()
    runner = AsyncMock(return_value=report)
    client = _build_client(runner=runner)

    response = client.post(
        "/analyze",
        json={
            "target_description": "FastAPI + pgvector RAG over OpenAI, no auth.",
            "session_id": "sess-abc",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == report.id
    assert body["target_description"] == report.target_description
    runner.assert_awaited_once()
    args, kwargs = runner.call_args
    assert args[0] == "FastAPI + pgvector RAG over OpenAI, no auth."
    assert kwargs == {"session_id": "sess-abc"}


def test_post_analyze_generates_session_id_when_omitted(
    sample_threat_report: Callable[..., Any],
) -> None:
    report = sample_threat_report()
    runner = AsyncMock(return_value=report)
    client = _build_client(runner=runner)

    response = client.post(
        "/analyze",
        json={
            "target_description": "A target architecture that is long enough.",
        },
    )

    assert response.status_code == 200
    kwargs = runner.call_args.kwargs
    assert kwargs["session_id"]  # non-empty UUID


def test_post_analyze_rejects_short_description() -> None:
    """AnalyzeRequest enforces min_length=20 — FastAPI returns 422."""
    client = _build_client(runner=AsyncMock())
    response = client.post("/analyze", json={"target_description": "too short"})
    assert response.status_code == 422


def test_post_analyze_returns_500_on_agent_error() -> None:
    runner = AsyncMock(side_effect=AgentError("planner blew up"))
    client = _build_client(runner=runner)

    response = client.post(
        "/analyze",
        json={"target_description": "An architecture long enough to satisfy the validator."},
    )

    assert response.status_code == 500
    detail = response.json()["detail"]
    assert detail["error_type"] == "AgentError"
    assert "planner blew up" in detail["error"]


# ---------------------------------------------------------------------------
# GET /analyze/stream — SSE
# ---------------------------------------------------------------------------


def test_get_analyze_stream_emits_sse_events() -> None:
    events = [
        AgentEvent(
            session_id="sess-stream",
            agent="pipeline",
            event_type="started",
            payload={},
        ),
        AgentEvent(
            session_id="sess-stream",
            agent="planner",
            event_type="node_completed",
            payload={"plan_count": 4},
        ),
        AgentEvent(
            session_id="sess-stream",
            agent="pipeline",
            event_type="completed",
            payload={},
        ),
    ]

    async def fake_stream(target: str, session_id: str | None = None) -> AsyncIterator[AgentEvent]:
        assert target == "Architecture description meeting the length minimum for SSE."
        for event in events:
            yield event

    client = _build_client(streamer=fake_stream)

    with client.stream(
        "GET",
        "/analyze/stream",
        params={
            "target_description": "Architecture description meeting the length minimum for SSE.",
            "session_id": "sess-stream",
        },
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = b"".join(response.iter_bytes()).decode()

    frames = [frame for frame in body.split("\n\n") if frame]
    assert len(frames) == 3
    first = json.loads(frames[0].removeprefix("data: "))
    assert first["event_type"] == "started"
    assert first["session_id"] == "sess-stream"
    completed = json.loads(frames[-1].removeprefix("data: "))
    assert completed["event_type"] == "completed"


# ---------------------------------------------------------------------------
# GET /report/{report_id}
# ---------------------------------------------------------------------------


def _summary_row() -> dict[str, Any]:
    return {
        "id": "report-fixture-0001",
        "session_id": "sess-from-db",
        "target_description": "Stored target",
        "created_at": "2026-05-14T12:00:00+00:00",
        "surface_count": 3,
        "severity_breakdown": json.dumps({"critical": 1, "high": 2, "medium": 0, "low": 0}),
        "focus_areas_covered": json.dumps(["injection", "data_leakage"]),
        "top_attack_vectors": json.dumps(["v1", "v2"]),
        "overall_critic_score": 0.82,
        "iteration_count": 1,
    }


def _pool_with_row(row: dict[str, Any] | None) -> Any:
    conn = MagicMock()
    conn.fetchrow = AsyncMock(return_value=row)
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


def test_get_report_returns_summary_when_present() -> None:
    pool = _pool_with_row(_summary_row())
    client = _build_client(pg_pool=pool)

    response = client.get("/report/report-fixture-0001")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "report-fixture-0001"
    assert body["surface_count"] == 3


def test_get_report_returns_404_when_absent() -> None:
    pool = _pool_with_row(None)
    client = _build_client(pg_pool=pool)
    response = client.get("/report/missing")
    assert response.status_code == 404


def test_get_report_returns_404_when_pool_unavailable() -> None:
    client = _build_client(pg_pool=None)
    response = client.get("/report/missing")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


def test_health_reports_ok_when_both_reachable() -> None:
    redis_client = MagicMock()
    redis_client.ping = AsyncMock(return_value=True)

    conn = MagicMock()
    conn.execute = AsyncMock(return_value=None)
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquire_cm)

    client = _build_client(redis_client=redis_client, pg_pool=pool)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "redis": True, "postgres": True}


def test_health_reports_degraded_when_resources_missing() -> None:
    client = _build_client(redis_client=None, pg_pool=None)
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body == {"status": "degraded", "redis": False, "postgres": False}


def test_health_reports_degraded_when_postgres_query_fails() -> None:
    redis_client = MagicMock()
    redis_client.ping = AsyncMock(return_value=True)

    conn = MagicMock()
    conn.execute = AsyncMock(side_effect=RuntimeError("pg dead"))
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquire_cm)

    client = _build_client(redis_client=redis_client, pg_pool=pool)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "degraded", "redis": True, "postgres": False}


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def test_cors_allows_frontend_origin() -> None:
    client = _build_client()
    response = client.options(
        "/analyze",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


# Stop pytest from emitting a "PytestUnraisableException" if any of the
# AsyncMock side-effects leak through teardown.
@pytest.fixture(autouse=True)
def _silence_unraisable() -> None:
    return None
