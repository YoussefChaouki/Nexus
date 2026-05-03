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
