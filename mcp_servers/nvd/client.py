"""Async HTTP client wrapping the NVD CVE REST API v2.

Features:
    * API-key-aware rate limiting: 5 req/s without key, 50 req/s with key
      (``NVD_API_KEY`` env var). Both rates can be overridden via constructor.
    * Retry with exponential back-off on HTTP 429, 403, and 5xx, honouring
      the ``Retry-After`` response header when present.
    * JSON parsing into :class:`CVEEntry` models for v3.1 / v3.0 / v2 metrics.

The client raises :class:`NVDAPIError` for all retryable and non-retryable
failures; the MCP server layer converts these into ``MCPToolError`` JSON
payloads so MCP clients never see raw exceptions.
"""

from __future__ import annotations

import asyncio
import os
import time
from types import TracebackType
from typing import Any, Final

import httpx
import structlog
from schemas import CVEEntry
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

logger = structlog.get_logger(__name__)

NVD_BASE_URL: Final[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_NO_KEY: Final[float] = 5.0
RATE_LIMIT_WITH_KEY: Final[float] = 50.0
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
DEFAULT_MAX_RETRIES: Final[int] = 3
ALLOWED_SEVERITIES: Final[frozenset[str]] = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})


class NVDAPIError(Exception):
    """Raised by :class:`NVDClient` on any failure to reach or parse NVD."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


class _RateLimiter:
    """Sleep-based limiter capping calls at one per ``min_interval`` seconds."""

    def __init__(self, min_interval: float) -> None:
        self._min_interval = min_interval
        self._lock = asyncio.Lock()
        self._next_time = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._next_time - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next_time = now + self._min_interval


class NVDClient:
    """Async client for the NVD CVE REST API v2."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        api_key: str | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        rate_limit_per_second: float | None = None,
    ) -> None:
        if api_key is None:
            api_key = os.environ.get("NVD_API_KEY")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS)
        self._owns_client = client is None
        if rate_limit_per_second is None:
            rate_limit_per_second = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_NO_KEY
        self._effective_rate = rate_limit_per_second
        self._limiter = _RateLimiter(1.0 / rate_limit_per_second)
        self._max_retries = max_retries

    @property
    def rate_limit_per_second(self) -> float:
        """Effective rate cap used by this client (post env detection)."""
        return self._effective_rate

    async def __aenter__(self) -> NVDClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying httpx client when this instance owns it."""
        if self._owns_client:
            await self._client.aclose()

    async def search_keyword(
        self,
        keyword: str,
        severity: str | None = None,
        max_results: int = 20,
    ) -> list[CVEEntry]:
        """Search CVEs by keyword, optionally filtered by CVSS v3 severity.

        Args:
            keyword: Free-form text searched in CVE descriptions.
            severity: One of ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, or
                ``None`` (case-insensitive).
            max_results: Page size sent as ``resultsPerPage``.

        Raises:
            NVDAPIError: If ``severity`` is not a valid value.
        """
        normalized_severity: str | None = None
        if severity is not None:
            normalized_severity = severity.upper()
            if normalized_severity not in ALLOWED_SEVERITIES:
                raise NVDAPIError(
                    f"invalid severity '{severity}', must be one of {sorted(ALLOWED_SEVERITIES)}",
                    retryable=False,
                )
        params: dict[str, str] = {
            "keywordSearch": keyword,
            "resultsPerPage": str(max_results),
        }
        if normalized_severity is not None:
            params["cvssV3Severity"] = normalized_severity
        data = await self._request(params)
        return _parse_cves(data)

    async def get_by_id(self, cve_id: str) -> CVEEntry:
        """Fetch a single CVE by its identifier.

        Raises:
            NVDAPIError: If the ID resolves to no entries.
        """
        params = {"cveId": cve_id}
        data = await self._request(params)
        cves = _parse_cves(data)
        if not cves:
            raise NVDAPIError(f"CVE not found: {cve_id}", retryable=False)
        return cves[0]

    async def search_by_product(self, cpe_name: str, max_results: int = 10) -> list[CVEEntry]:
        """Search CVEs affecting a specific product by CPE 2.3 name."""
        params = {"cpeName": cpe_name, "resultsPerPage": str(max_results)}
        data = await self._request(params)
        return _parse_cves(data)

    async def _request(self, params: dict[str, str]) -> dict[str, Any]:
        """Issue a rate-limited GET with retry on retryable failures."""

        def _is_retryable(exc: BaseException) -> bool:
            return isinstance(exc, NVDAPIError) and exc.retryable

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception(_is_retryable),
            reraise=True,
        ):
            with attempt:
                return await self._do_request(params)
        raise NVDAPIError("retry loop exhausted without raising", retryable=False)

    async def _do_request(self, params: dict[str, str]) -> dict[str, Any]:
        await self._limiter.acquire()
        headers = {"apiKey": self._api_key} if self._api_key else {}
        try:
            response = await self._client.get(NVD_BASE_URL, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise NVDAPIError(f"network error: {exc}", retryable=True) from exc

        status = response.status_code
        if status in (403, 429):
            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
            if retry_after is not None and retry_after > 0:
                await asyncio.sleep(retry_after)
            raise NVDAPIError(
                f"NVD rate limit / forbidden ({status})",
                retryable=True,
                retry_after=retry_after,
            )
        if 500 <= status < 600:
            raise NVDAPIError(f"NVD server error {status}", retryable=True)
        if status != 200:
            raise NVDAPIError(f"unexpected NVD status {status}", retryable=False)

        try:
            data = response.json()
        except ValueError as exc:
            raise NVDAPIError(f"invalid NVD JSON: {exc}", retryable=False) from exc
        if not isinstance(data, dict):
            raise NVDAPIError("NVD response is not a JSON object", retryable=False)
        return data


def _parse_retry_after(value: str | None) -> float | None:
    """Parse the ``Retry-After`` header. Returns seconds, or None on parse error.

    Only the integer-seconds form is supported (the HTTP-date form is rare for
    NVD and would require ``email.utils.parsedate_to_datetime``; ignored to keep
    the implementation small).
    """
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _parse_cves(data: dict[str, Any]) -> list[CVEEntry]:
    """Map the NVD ``vulnerabilities`` array into :class:`CVEEntry` objects."""
    items = data.get("vulnerabilities", [])
    if not isinstance(items, list):
        return []
    return [
        _one_cve(item.get("cve", {}))
        for item in items
        if isinstance(item, dict) and isinstance(item.get("cve"), dict)
    ]


def _one_cve(cve: dict[str, Any]) -> CVEEntry:
    cve_id = str(cve.get("id", ""))
    description = _en_description(cve.get("descriptions", []))
    severity, score = _cvss(cve.get("metrics", {}))
    references = _references(cve.get("references", []))
    products = _affected_products(cve.get("configurations", []))

    return CVEEntry(
        cve_id=cve_id,
        description=description,
        severity=severity,
        cvss_score=score,
        published_date=str(cve.get("published", "")),
        last_modified_date=str(cve.get("lastModified", "")),
        affected_products=products,
        references=references,
    )


def _en_description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            value = item.get("value", "")
            return str(value) if value is not None else ""
    return ""


def _cvss(metrics: Any) -> tuple[str | None, float | None]:
    if not isinstance(metrics, dict):
        return (None, None)
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key)
        if not isinstance(rows, list) or not rows:
            continue
        first = rows[0]
        if not isinstance(first, dict):
            continue
        cvss_data = first.get("cvssData")
        if not isinstance(cvss_data, dict):
            continue
        raw_score = cvss_data.get("baseScore")
        score = float(raw_score) if isinstance(raw_score, int | float) else None
        severity_raw = cvss_data.get("baseSeverity") or first.get("baseSeverity")
        severity = str(severity_raw) if severity_raw else None
        return (severity, score)
    return (None, None)


def _references(refs: Any) -> list[str]:
    if not isinstance(refs, list):
        return []
    out: list[str] = []
    for ref in refs:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            out.append(ref["url"])
    return out


def _affected_products(configurations: Any) -> list[str]:
    if not isinstance(configurations, list):
        return []
    out: list[str] = []
    for cfg in configurations:
        if not isinstance(cfg, dict):
            continue
        nodes = cfg.get("nodes", [])
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            cpe_matches = node.get("cpeMatch", [])
            if not isinstance(cpe_matches, list):
                continue
            for cpe in cpe_matches:
                if isinstance(cpe, dict) and isinstance(cpe.get("criteria"), str):
                    out.append(cpe["criteria"])
    return out
