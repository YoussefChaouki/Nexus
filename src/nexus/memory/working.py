"""Redis working memory — connection management and LangGraph checkpointer factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast

import structlog
from redis.asyncio import Redis
from redis.asyncio.connection import ConnectionPool
from redis.exceptions import RedisError

from nexus.exceptions import MemoryLayerError
from nexus.settings import get_settings

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def get_redis_client() -> AsyncIterator[Redis]:
    """Yield a connected async Redis client from a capped connection pool.

    Raises:
        MemoryLayerError: If the connection cannot be established.
    """
    settings = get_settings()
    pool: Any = ConnectionPool.from_url(
        settings.redis_url,
        max_connections=10,
        decode_responses=False,
    )
    client: Redis = Redis(connection_pool=pool)
    try:
        yield client
    except (RedisError, OSError) as exc:
        raise MemoryLayerError(f"Redis connection error: {exc}") from exc
    finally:
        await client.aclose()
        await pool.aclose()


def get_checkpointer(redis_client: Redis) -> Any:  # noqa: ANN401
    """Create a LangGraph AsyncRedisSaver for pipeline working memory.

    Justified Any return: AsyncRedisSaver has no stable public type across LangGraph versions.
    Falls back to MemorySaver when langgraph-checkpoint-redis is not installed.

    Args:
        redis_client: Connected async Redis client.

    Returns:
        AsyncRedisSaver or MemorySaver (BaseCheckpointSaver subclass).
    """
    try:
        from langgraph.checkpoint.redis.aio import AsyncRedisSaver

        return AsyncRedisSaver(redis_client)
    except ImportError:
        logger.warning(
            "redis_saver_fallback",
            reason="langgraph-checkpoint-redis not installed — using MemorySaver",
        )
        from langgraph.checkpoint.memory import MemorySaver

        return MemorySaver()


async def check_redis_health(client: Redis) -> bool:
    """Ping Redis and return True if healthy.

    Args:
        client: Connected async Redis client.

    Returns:
        True if Redis responds to PING, False on any error.
    """
    try:
        # client.ping() is typed as Awaitable[bool] | bool by newer redis
        # stubs and plain Awaitable[bool] by older ones; cast to Any so the
        # await is valid (and the cast never redundant) across both.
        return bool(await cast("Any", client.ping()))
    except (RedisError, OSError) as exc:
        logger.warning("redis_health_failed", error=str(exc))
        return False
