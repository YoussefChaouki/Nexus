"""Tests for Redis working memory helpers."""

import pytest
from fakeredis.aioredis import FakeRedis

from nexus.memory.working import check_redis_health, get_checkpointer


@pytest.fixture()
async def fake_redis() -> FakeRedis:  # type: ignore[type-arg]
    return FakeRedis()


async def test_check_redis_health_returns_true(fake_redis: FakeRedis) -> None:  # type: ignore[type-arg]
    assert await check_redis_health(fake_redis) is True  # type: ignore[arg-type]


async def test_check_redis_health_returns_false_on_error() -> None:
    from unittest.mock import AsyncMock, patch

    with patch("nexus.memory.working.Redis.ping", new_callable=AsyncMock) as mock_ping:
        from redis.exceptions import ConnectionError as RedisConnectionError

        mock_ping.side_effect = RedisConnectionError("refused")
        client: FakeRedis = FakeRedis()  # type: ignore[type-arg]
        result = await check_redis_health(client)  # type: ignore[arg-type]
        assert result is False


async def test_get_checkpointer_returns_checkpointer(fake_redis: FakeRedis) -> None:  # type: ignore[type-arg]
    checkpointer = get_checkpointer(fake_redis)  # type: ignore[arg-type]
    assert checkpointer is not None


async def test_get_checkpointer_has_expected_interface(fake_redis: FakeRedis) -> None:  # type: ignore[type-arg]
    checkpointer = get_checkpointer(fake_redis)  # type: ignore[arg-type]
    # BaseCheckpointSaver subclasses must expose aget / aput (LangGraph contract)
    assert hasattr(checkpointer, "put") or hasattr(checkpointer, "aget")


async def test_get_redis_client_yields_connected_client() -> None:
    """Exercises the connection-pool wiring without hitting a real Redis.

    We patch ``ConnectionPool.from_url`` so the context manager builds a
    client backed by an in-memory fake. The contract under test: a
    client is yielded *and* the pool / client are closed on exit.
    """
    from unittest.mock import AsyncMock, MagicMock, patch

    from nexus.memory.working import get_redis_client

    fake_pool = MagicMock()
    fake_pool.aclose = AsyncMock(return_value=None)
    with patch(
        "nexus.memory.working.ConnectionPool.from_url",
        return_value=fake_pool,
    ):
        async with get_redis_client() as client:
            assert client is not None
            # The client.aclose is owned by the Redis class; the
            # context manager closes both client + pool on exit.

    fake_pool.aclose.assert_awaited()


async def test_get_redis_client_translates_redis_error() -> None:
    """A redis.exceptions.RedisError inside the block becomes MemoryLayerError."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from redis.exceptions import RedisError

    from nexus.exceptions import MemoryLayerError
    from nexus.memory.working import get_redis_client

    fake_pool = MagicMock()
    fake_pool.aclose = AsyncMock(return_value=None)
    with patch(
        "nexus.memory.working.ConnectionPool.from_url",
        return_value=fake_pool,
    ):
        with pytest.raises(MemoryLayerError, match="Redis connection error"):
            async with get_redis_client():
                raise RedisError("pool refused")

    fake_pool.aclose.assert_awaited()


def test_get_checkpointer_falls_back_to_memory_saver_when_import_fails(
    fake_redis: FakeRedis,  # type: ignore[type-arg]
) -> None:
    """When ``langgraph.checkpoint.redis.aio`` is missing, use MemorySaver."""
    import builtins
    from unittest.mock import patch

    original_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "langgraph.checkpoint.redis.aio":
            raise ImportError("not installed")
        return original_import(name, *args, **kwargs)  # type: ignore[arg-type]

    with patch("builtins.__import__", side_effect=fake_import):
        checkpointer = get_checkpointer(fake_redis)  # type: ignore[arg-type]

    from langgraph.checkpoint.memory import MemorySaver

    assert isinstance(checkpointer, MemorySaver)
