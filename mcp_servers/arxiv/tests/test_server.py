"""Tests for the arXiv MCP server.

The arXiv API is mocked entirely with respx. Tests exercise the MCP tool
functions directly (FastMCP's ``@tool()`` decorator preserves the original
async callable) and validate that returned JSON parses back into the
public schema models.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator

import httpx
import pytest
import respx
from client import ARXIV_API_URL, ArxivClient
from schemas import ArxivPaper, MCPToolError
from server import (
    get_full_text,
    get_paper_abstract,
    search_papers,
    set_client,
)

SEARCH_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>http://arxiv.org/abs/2401.12345v1</id>
    <updated>2024-01-23T10:00:00Z</updated>
    <published>2024-01-22T09:00:00Z</published>
    <title>Prompt Injection Survey</title>
    <summary>A comprehensive survey of prompt injection vectors against LLM apps.</summary>
    <author><name>Alice Researcher</name></author>
    <author><name>Bob Engineer</name></author>
    <link rel="alternate" href="http://arxiv.org/abs/2401.12345v1"/>
    <category term="cs.CR"/>
    <category term="cs.AI"/>
  </entry>
  <entry>
    <id>http://arxiv.org/abs/2402.00001v2</id>
    <updated>2024-02-02T10:00:00Z</updated>
    <published>2024-02-01T09:00:00Z</published>
    <title>Indirect Prompt Injection in RAG</title>
    <summary>Analyzing prompt injection through retrieved documents in RAG pipelines.</summary>
    <author><name>Carol Hacker</name></author>
    <link rel="alternate" href="http://arxiv.org/abs/2402.00001v2"/>
    <category term="cs.CR"/>
  </entry>
</feed>
"""


SINGLE_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>http://arxiv.org/abs/2401.12345v1</id>
    <updated>2024-01-23T10:00:00Z</updated>
    <published>2024-01-22T09:00:00Z</published>
    <title>Prompt Injection Survey</title>
    <summary>A comprehensive survey of prompt injection vectors against LLM apps.</summary>
    <author><name>Alice Researcher</name></author>
    <link rel="alternate" href="http://arxiv.org/abs/2401.12345v1"/>
    <category term="cs.CR"/>
  </entry>
</feed>
"""


EMPTY_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"></feed>
"""


@pytest.fixture(autouse=True)
async def fast_client() -> AsyncIterator[ArxivClient]:
    """Inject a fast (~0 wait) client and reset the global after each test."""
    client = ArxivClient(rate_limit_per_second=1000.0, max_retries=3)
    set_client(client)
    try:
        yield client
    finally:
        await client.aclose()
        set_client(None)


async def test_search_papers_returns_valid_json_list() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(200, text=SEARCH_FEED))
        raw = await search_papers(query="prompt injection", max_results=5)

    parsed = json.loads(raw)
    assert isinstance(parsed, list)
    papers = [ArxivPaper.model_validate(item) for item in parsed]
    assert len(papers) == 2
    assert papers[0].arxiv_id == "2401.12345v1"
    assert papers[0].authors == ["Alice Researcher", "Bob Engineer"]
    assert "cs.CR" in papers[0].categories


async def test_get_paper_abstract_returns_valid_paper_json() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(200, text=SINGLE_FEED))
        raw = await get_paper_abstract(arxiv_id="2401.12345v1")

    paper = ArxivPaper.model_validate_json(raw)
    assert paper.arxiv_id == "2401.12345v1"
    assert paper.abstract.startswith("A comprehensive survey")


async def test_get_full_text_falls_back_to_abstract() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(200, text=SINGLE_FEED))
        raw = await get_full_text(arxiv_id="2401.12345v1")

    paper = ArxivPaper.model_validate_json(raw)
    assert paper.full_text is not None
    assert paper.full_text == paper.abstract


async def test_get_paper_abstract_unknown_id_returns_error() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(200, text=EMPTY_FEED))
        raw = await get_paper_abstract(arxiv_id="9999.99999")

    error = MCPToolError.model_validate_json(raw)
    assert error.error_type == "arxiv_api_error"
    assert "9999.99999" in error.error
    assert error.retryable is False


async def test_rate_limit_three_rapid_calls_complete(fast_client: ArxivClient) -> None:
    """Three rapid calls under a 3 req/s limit complete without error."""
    set_client(ArxivClient(rate_limit_per_second=3.0, max_retries=1))
    try:
        with respx.mock(assert_all_called=False) as router:
            router.get(ARXIV_API_URL).mock(return_value=httpx.Response(200, text=SEARCH_FEED))
            results = await asyncio.gather(
                search_papers(query="a"),
                search_papers(query="b"),
                search_papers(query="c"),
            )
        for raw in results:
            parsed = json.loads(raw)
            assert isinstance(parsed, list)
    finally:
        # autouse fixture's teardown closes/resets, but reset eagerly to be safe
        pass


async def test_rate_limiter_paces_calls() -> None:
    """Two back-to-back calls at 5 req/s should take ≥ 1/5 second."""
    set_client(ArxivClient(rate_limit_per_second=5.0, max_retries=1))
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(200, text=EMPTY_FEED))
        start = time.monotonic()
        await search_papers(query="a")
        await search_papers(query="b")
        elapsed = time.monotonic() - start
    assert elapsed >= 0.18  # allow scheduling slack


async def test_429_returns_mcp_error_with_retryable_true() -> None:
    set_client(ArxivClient(rate_limit_per_second=1000.0, max_retries=2))
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(429, text=""))
        raw = await search_papers(query="anything")

    error = MCPToolError.model_validate_json(raw)
    assert error.error_type == "arxiv_api_error"
    assert error.retryable is True


async def test_500_returns_mcp_error_with_retryable_true() -> None:
    set_client(ArxivClient(rate_limit_per_second=1000.0, max_retries=2))
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(503, text=""))
        raw = await search_papers(query="anything")

    error = MCPToolError.model_validate_json(raw)
    assert error.retryable is True


async def test_400_returns_non_retryable_error() -> None:
    set_client(ArxivClient(rate_limit_per_second=1000.0, max_retries=1))
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(400, text=""))
        raw = await search_papers(query="bad")

    error = MCPToolError.model_validate_json(raw)
    assert error.retryable is False


async def test_invalid_xml_returns_non_retryable_error() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(ARXIV_API_URL).mock(return_value=httpx.Response(200, text="<not-xml"))
        raw = await search_papers(query="x")

    error = MCPToolError.model_validate_json(raw)
    assert error.retryable is False
