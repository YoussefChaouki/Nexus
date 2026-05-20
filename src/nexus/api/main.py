"""FastAPI entry point for NEXUS.

Endpoints
---------
* ``POST /analyze`` — run the full pipeline synchronously and return a
  :class:`ThreatReport`.
* ``GET /analyze/stream`` — SSE stream of :class:`AgentEvent` payloads
  as the pipeline progresses. Designed for the Next.js frontend.
* ``GET /report/{report_id}`` — fetch a previously persisted
  :class:`ThreatReportSummary` from episodic memory.
* ``GET /health`` — Redis + Postgres reachability probe used by Docker.

Resources (Redis client, asyncpg pool) live for the lifetime of the
ASGI app via :func:`fastapi.FastAPI` lifespan. Tests construct a fresh
app with :func:`create_app` and dependency overrides so they never
touch real infrastructure.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from nexus.exceptions import AgentError
from nexus.graph.graph import run_pipeline
from nexus.graph.streaming import stream_pipeline_events
from nexus.memory.episodic import EpisodicMemory
from nexus.memory.report_cache import get_report_cache
from nexus.memory.working import check_redis_health
from nexus.schemas.models import AgentEvent, AnalyzeRequest, ThreatReport, ThreatReportSummary

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Lifespan — Redis client + asyncpg pool
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open and tear down shared infra resources.

    Failures are logged but not fatal — the API stays up even when
    Redis or Postgres is unavailable so ``/health`` can report the
    issue instead of refusing connections.
    """
    redis_client: Any = None
    pg_pool: Any = None
    try:
        from redis.asyncio import Redis

        from nexus.settings import get_settings

        settings = get_settings()
        try:
            redis_client = Redis.from_url(settings.redis_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("redis_init_failed", error=str(exc))
            redis_client = None

        try:
            import asyncpg

            pg_pool = await asyncpg.create_pool(
                dsn=_to_asyncpg_dsn(settings.postgres_dsn),
                min_size=1,
                max_size=5,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("postgres_init_failed", error=str(exc))
            pg_pool = None

        app.state.redis_client = redis_client
        app.state.pg_pool = pg_pool
        yield
    finally:
        if redis_client is not None:
            try:
                await redis_client.aclose()
            except Exception as exc:  # noqa: BLE001
                logger.warning("redis_close_failed", error=str(exc))
        if pg_pool is not None:
            try:
                await pg_pool.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("pg_pool_close_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Dependency providers — overridable in tests
# ---------------------------------------------------------------------------


async def get_redis(app_state: Any = None) -> Any:  # noqa: ANN401
    """Return the lifespan-managed Redis client (or ``None`` in tests)."""
    return None


async def get_pg_pool() -> Any:  # noqa: ANN401
    """Return the lifespan-managed asyncpg pool (or ``None`` in tests)."""
    return None


async def get_pipeline_runner() -> Any:  # noqa: ANN401
    """Return the callable used to execute the pipeline.

    Wrapped behind a dependency so tests can swap in a stub without
    monkeypatching imports.
    """
    return run_pipeline


async def get_pipeline_streamer() -> Any:  # noqa: ANN401
    """Return the async-iterator factory for SSE streaming."""
    return stream_pipeline_events


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Build and configure the NEXUS FastAPI application."""
    app = FastAPI(
        title="NEXUS Threat Modelling API",
        version="0.1.0",
        lifespan=_lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ----- POST /analyze ---------------------------------------------------

    @app.post("/analyze", response_model=ThreatReport)
    async def analyze(
        request: AnalyzeRequest,
        runner: Any = Depends(get_pipeline_runner),
        pool: Any = Depends(get_pg_pool),
    ) -> ThreatReport:
        """Run the pipeline end-to-end and return the final report."""
        session_id = request.session_id or str(uuid4())
        try:
            return await runner(  # type: ignore[no-any-return]
                request.target_description,
                session_id=session_id,
                pg_pool=pool,
            )
        except AgentError as exc:
            logger.warning(
                "analyze_failed",
                session_id=session_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": str(exc), "error_type": type(exc).__name__},
            ) from exc

    # ----- GET /analyze/stream --------------------------------------------

    @app.get("/analyze/stream")
    async def analyze_stream(
        target_description: str = Query(..., min_length=20, max_length=2000),
        session_id: str | None = Query(default=None),
        streamer: Any = Depends(get_pipeline_streamer),
        pool: Any = Depends(get_pg_pool),
    ) -> StreamingResponse:
        """Stream pipeline progress as Server-Sent Events."""
        resolved_id = session_id or str(uuid4())

        async def event_source() -> AsyncIterator[bytes]:
            async for event in streamer(target_description, session_id=resolved_id, pg_pool=pool):
                yield _format_sse(event)

        return StreamingResponse(
            event_source(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # ----- GET /report/{report_id} ----------------------------------------

    @app.get("/report/{report_id}", response_model=ThreatReportSummary)
    async def get_report(
        report_id: str,
        pool: Any = Depends(get_pg_pool),
    ) -> ThreatReportSummary:
        """Fetch a ``ThreatReportSummary`` by id.

        Resolution order:
            1. Process-local cache populated by the writer on every run —
               survives pgvector outages and missing OpenAI embeddings.
            2. Episodic memory in pgvector — the durable backing store.

        Returns 404 only when both layers miss.
        """
        cached = get_report_cache().get(report_id)
        if cached is not None:
            return cached
        if pool is not None:
            memory = EpisodicMemory(pool=pool)
            persisted = await memory.get_by_id(report_id)
            if persisted is not None:
                return persisted
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="report not found",
        )

    # ----- GET /health ----------------------------------------------------

    @app.get("/health")
    async def health(
        redis_client: Any = Depends(get_redis),
        pool: Any = Depends(get_pg_pool),
    ) -> dict[str, Any]:
        """Probe Redis + Postgres reachability."""
        redis_ok = False
        if redis_client is not None:
            try:
                redis_ok = await check_redis_health(redis_client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("health_redis_failed", error=str(exc))
                redis_ok = False
        pg_ok = False
        if pool is not None:
            try:
                async with pool.acquire() as conn:
                    await conn.execute("SELECT 1")
                pg_ok = True
            except Exception as exc:  # noqa: BLE001
                logger.warning("health_postgres_failed", error=str(exc))
                pg_ok = False
        return {
            "status": "ok" if (redis_ok and pg_ok) else "degraded",
            "redis": redis_ok,
            "postgres": pg_ok,
        }

    # Wire the lifespan-managed resources into the dependency overrides.
    # Default providers above return ``None`` so unit tests stay hermetic;
    # the real runtime reads from ``app.state`` populated in ``_lifespan``.
    async def _runtime_get_redis() -> Any:
        return getattr(app.state, "redis_client", None)

    async def _runtime_get_pg_pool() -> Any:
        return getattr(app.state, "pg_pool", None)

    app.dependency_overrides[get_redis] = _runtime_get_redis
    app.dependency_overrides[get_pg_pool] = _runtime_get_pg_pool

    return app


def _format_sse(event: AgentEvent) -> bytes:
    """Encode an :class:`AgentEvent` as an SSE ``data:`` frame."""
    payload = event.model_dump(mode="json")
    return f"data: {json.dumps(payload)}\n\n".encode()


def _to_asyncpg_dsn(dsn: str) -> str:
    """Strip SQLAlchemy-style driver suffix that asyncpg doesn't accept.

    Settings stores ``postgresql+asyncpg://…`` to document the intended
    driver, but :func:`asyncpg.create_pool` only understands ``postgresql://``
    or ``postgres://``. Normalising here keeps the canonical form in
    ``.env`` while still booting the pool.
    """
    return dsn.replace("postgresql+asyncpg://", "postgresql://", 1)


# Module-level app instance for ``uvicorn nexus.api.main:app``.
app: FastAPI = create_app()
