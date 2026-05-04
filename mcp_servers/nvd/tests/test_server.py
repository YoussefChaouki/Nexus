"""Tests for the NVD CVE MCP server.

The NVD API is mocked entirely with respx using the real v2 response
shape. Tests exercise the MCP tool functions directly (FastMCP's
``@tool()`` decorator preserves the original async callable) and validate
that returned JSON parses back into the public schema models.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import respx
from client import (
    NVD_BASE_URL,
    RATE_LIMIT_NO_KEY,
    RATE_LIMIT_WITH_KEY,
    NVDClient,
)
from schemas import CVEEntry, MCPToolError
from server import (
    get_cve_detail,
    search_by_product,
    search_cves,
    set_client,
)

# Realistic NVD v2 response payload
SEARCH_RESPONSE: dict[str, Any] = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-12345",
                "published": "2024-01-15T00:00:00.000",
                "lastModified": "2024-02-01T00:00:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Buffer overflow in foo allows remote code execution.",
                    },
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        },
                    ],
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:foo:foo:1.0:*:*:*:*:*:*:*",
                                    },
                                ],
                            },
                        ],
                    },
                ],
                "references": [{"url": "https://example.com/advisory/1"}],
            },
        },
        {
            "cve": {
                "id": "CVE-2024-67890",
                "published": "2024-03-01T00:00:00.000",
                "lastModified": "2024-03-05T00:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "XSS in bar admin panel."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {"baseScore": 6.1, "baseSeverity": "MEDIUM"},
                        },
                    ],
                },
                "configurations": [],
                "references": [],
            },
        },
    ],
}


SINGLE_RESPONSE: dict[str, Any] = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [SEARCH_RESPONSE["vulnerabilities"][0]],
}


EMPTY_RESPONSE: dict[str, Any] = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": [],
}


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default to no API key so tests are deterministic."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)


@pytest.fixture()
async def fast_client() -> AsyncIterator[NVDClient]:
    """Inject a fast (~0 wait) client and reset the global after each test."""
    client = NVDClient(api_key=None, rate_limit_per_second=1000.0, max_retries=3)
    set_client(client)
    try:
        yield client
    finally:
        await client.aclose()
        set_client(None)


async def test_search_cves_returns_valid_json_list(fast_client: NVDClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(
            return_value=httpx.Response(200, json=SEARCH_RESPONSE),
        )
        raw = await search_cves(keyword="buffer overflow", max_results=10)

    parsed = json.loads(raw)
    assert isinstance(parsed, list)
    cves = [CVEEntry.model_validate(item) for item in parsed]
    assert len(cves) == 2
    assert cves[0].cve_id == "CVE-2024-12345"
    assert cves[0].severity == "CRITICAL"
    assert cves[0].cvss_score == 9.8
    assert "cpe:2.3:a:foo:foo:1.0" in cves[0].affected_products[0]


async def test_search_cves_with_severity_filter_passes_param(
    fast_client: NVDClient,
) -> None:
    captured: dict[str, str] = {}

    def hook(request: httpx.Request) -> httpx.Response:
        captured.update(dict(request.url.params))
        return httpx.Response(200, json=SEARCH_RESPONSE)

    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(side_effect=hook)
        await search_cves(keyword="rce", severity="HIGH")

    assert captured.get("cvssV3Severity") == "HIGH"
    assert captured.get("keywordSearch") == "rce"


async def test_search_cves_without_severity_omits_param(
    fast_client: NVDClient,
) -> None:
    captured: dict[str, str] = {}

    def hook(request: httpx.Request) -> httpx.Response:
        captured.update(dict(request.url.params))
        return httpx.Response(200, json=SEARCH_RESPONSE)

    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(side_effect=hook)
        await search_cves(keyword="rce")

    assert "cvssV3Severity" not in captured


async def test_search_cves_invalid_severity_returns_error(
    fast_client: NVDClient,
) -> None:
    raw = await search_cves(keyword="x", severity="WAT")
    err = MCPToolError.model_validate_json(raw)
    assert err.retryable is False
    assert "WAT" in err.error.upper()


async def test_get_cve_detail_returns_valid_cve(fast_client: NVDClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(
            return_value=httpx.Response(200, json=SINGLE_RESPONSE),
        )
        raw = await get_cve_detail(cve_id="CVE-2024-12345")

    cve = CVEEntry.model_validate_json(raw)
    assert cve.cve_id == "CVE-2024-12345"
    assert cve.cvss_score == 9.8


async def test_get_cve_detail_unknown_returns_error(fast_client: NVDClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(
            return_value=httpx.Response(200, json=EMPTY_RESPONSE),
        )
        raw = await get_cve_detail(cve_id="CVE-9999-99999")

    err = MCPToolError.model_validate_json(raw)
    assert err.retryable is False
    assert "CVE-9999-99999" in err.error


async def test_search_by_product_returns_list(fast_client: NVDClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(
            return_value=httpx.Response(200, json=SEARCH_RESPONSE),
        )
        raw = await search_by_product(cpe_name="cpe:2.3:a:foo:foo:*:*:*:*:*:*:*:*", max_results=5)

    parsed = json.loads(raw)
    assert isinstance(parsed, list)
    assert len(parsed) == 2


async def test_429_with_retry_after_returns_retryable_error() -> None:
    set_client(NVDClient(api_key=None, rate_limit_per_second=1000.0, max_retries=2))
    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(
            return_value=httpx.Response(429, headers={"Retry-After": "0"}, json={}),
        )
        raw = await search_cves(keyword="x")

    err = MCPToolError.model_validate_json(raw)
    assert err.retryable is True


async def test_403_treated_as_retryable() -> None:
    set_client(NVDClient(api_key=None, rate_limit_per_second=1000.0, max_retries=2))
    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(
            return_value=httpx.Response(403, headers={"Retry-After": "0"}, json={}),
        )
        raw = await search_cves(keyword="x")

    err = MCPToolError.model_validate_json(raw)
    assert err.retryable is True


async def test_500_treated_as_retryable() -> None:
    set_client(NVDClient(api_key=None, rate_limit_per_second=1000.0, max_retries=2))
    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(
            return_value=httpx.Response(503, json={}),
        )
        raw = await search_cves(keyword="x")

    err = MCPToolError.model_validate_json(raw)
    assert err.retryable is True


async def test_400_non_retryable() -> None:
    set_client(NVDClient(api_key=None, rate_limit_per_second=1000.0, max_retries=1))
    with respx.mock(assert_all_called=False) as router:
        router.get(NVD_BASE_URL).mock(return_value=httpx.Response(400, json={}))
        raw = await search_cves(keyword="bad")

    err = MCPToolError.model_validate_json(raw)
    assert err.retryable is False


async def test_no_api_key_uses_5_req_per_sec() -> None:
    client = NVDClient()
    try:
        assert client.rate_limit_per_second == RATE_LIMIT_NO_KEY
    finally:
        await client.aclose()


async def test_with_api_key_uses_50_req_per_sec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NVD_API_KEY", "fake-key")
    client = NVDClient()
    try:
        assert client.rate_limit_per_second == RATE_LIMIT_WITH_KEY
    finally:
        await client.aclose()


async def test_api_key_sent_as_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "secret-xyz")
    client = NVDClient(rate_limit_per_second=1000.0)
    set_client(client)
    captured_headers: dict[str, str] = {}

    def hook(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json=EMPTY_RESPONSE)

    try:
        with respx.mock(assert_all_called=False) as router:
            router.get(NVD_BASE_URL).mock(side_effect=hook)
            await search_cves(keyword="x")
        assert captured_headers.get("apikey") == "secret-xyz"
    finally:
        await client.aclose()
        set_client(None)


async def test_rate_limiter_paces_calls() -> None:
    """Two calls at 10 req/s must take at least ~0.08s including pacing."""
    client = NVDClient(api_key=None, rate_limit_per_second=10.0, max_retries=1)
    set_client(client)
    try:
        with respx.mock(assert_all_called=False) as router:
            router.get(NVD_BASE_URL).mock(
                return_value=httpx.Response(200, json=EMPTY_RESPONSE),
            )
            start = time.monotonic()
            await search_cves(keyword="a")
            await search_cves(keyword="b")
            elapsed = time.monotonic() - start
        assert elapsed >= 0.08
    finally:
        await client.aclose()
        set_client(None)
