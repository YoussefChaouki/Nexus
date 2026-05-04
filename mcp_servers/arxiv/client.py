"""Async HTTP client wrapping the arXiv Atom API.

Features:
    * Token-bucket rate limiting (default 3 req/s — the published arXiv limit).
    * Retry with exponential back-off on HTTP 429 and 5xx.
    * Atom/XML parsing into :class:`ArxivPaper` models.

The client raises :class:`ArxivAPIError` for all retryable and non-retryable
failures; the MCP server layer converts these into ``MCPToolError`` JSON
payloads so MCP clients never see raw exceptions.
"""

from __future__ import annotations

import asyncio
import time
from types import TracebackType
from typing import Final
from xml.etree import ElementTree as ET

import httpx
import structlog
from schemas import ArxivPaper
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

logger = structlog.get_logger(__name__)

ARXIV_API_URL: Final[str] = "http://export.arxiv.org/api/query"
ATOM_NS: Final[str] = "{http://www.w3.org/2005/Atom}"
DEFAULT_RATE_LIMIT_PER_SECOND: Final[float] = 3.0
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
DEFAULT_MAX_RETRIES: Final[int] = 3


class ArxivAPIError(Exception):
    """Raised by :class:`ArxivClient` on any failure to reach or parse arXiv."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


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


class ArxivClient:
    """Async client for the arXiv Atom API."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        rate_limit_per_second: float = DEFAULT_RATE_LIMIT_PER_SECOND,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self._client = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS)
        self._owns_client = client is None
        self._limiter = _RateLimiter(1.0 / rate_limit_per_second)
        self._max_retries = max_retries

    async def __aenter__(self) -> ArxivClient:
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

    async def search(self, query: str, max_results: int = 10) -> list[ArxivPaper]:
        """Search arXiv via ``search_query=all:<query>``.

        Args:
            query: Free-form search string (forwarded with ``all:`` prefix).
            max_results: Maximum number of papers to return.

        Returns:
            List of parsed papers, possibly empty.
        """
        params = {
            "search_query": f"all:{query}",
            "start": "0",
            "max_results": str(max_results),
        }
        text = await self._request(params)
        return _parse_feed(text)

    async def get_by_id(self, arxiv_id: str) -> ArxivPaper:
        """Fetch a single paper by its arXiv identifier.

        Raises:
            ArxivAPIError: If the ID resolves to no entries.
        """
        params = {"id_list": arxiv_id, "max_results": "1"}
        text = await self._request(params)
        papers = _parse_feed(text)
        if not papers:
            raise ArxivAPIError(f"arXiv ID not found: {arxiv_id}", retryable=False)
        return papers[0]

    async def _request(self, params: dict[str, str]) -> str:
        """Issue a rate-limited GET with retry on retryable failures."""

        def _is_retryable(exc: BaseException) -> bool:
            return isinstance(exc, ArxivAPIError) and exc.retryable

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception(_is_retryable),
            reraise=True,
        ):
            with attempt:
                return await self._do_request(params)
        raise ArxivAPIError("retry loop exhausted without raising", retryable=False)

    async def _do_request(self, params: dict[str, str]) -> str:
        await self._limiter.acquire()
        try:
            response = await self._client.get(ARXIV_API_URL, params=params)
        except httpx.HTTPError as exc:
            raise ArxivAPIError(f"network error: {exc}", retryable=True) from exc

        status = response.status_code
        if status == 429:
            raise ArxivAPIError("rate limited by arXiv", retryable=True)
        if 500 <= status < 600:
            raise ArxivAPIError(f"arXiv server error {status}", retryable=True)
        if status != 200:
            raise ArxivAPIError(f"unexpected arXiv status {status}", retryable=False)
        return response.text


def _parse_feed(xml_text: str) -> list[ArxivPaper]:
    """Parse an arXiv Atom feed body into :class:`ArxivPaper` objects."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ArxivAPIError(f"invalid arXiv XML: {exc}", retryable=False) from exc

    return [_entry_to_paper(entry) for entry in root.findall(f"{ATOM_NS}entry")]


def _entry_to_paper(entry: ET.Element) -> ArxivPaper:
    arxiv_id = _strip_arxiv_id(_text(entry, f"{ATOM_NS}id"))
    title = _text(entry, f"{ATOM_NS}title").strip()
    abstract = _text(entry, f"{ATOM_NS}summary").strip()
    published = _text(entry, f"{ATOM_NS}published").strip()

    url_link = ""
    for link in entry.findall(f"{ATOM_NS}link"):
        if link.attrib.get("rel") == "alternate":
            url_link = link.attrib.get("href", "")
            break
    if not url_link:
        url_link = f"http://arxiv.org/abs/{arxiv_id}"

    authors = [
        _text(author, f"{ATOM_NS}name").strip() for author in entry.findall(f"{ATOM_NS}author")
    ]
    categories = [
        cat.attrib["term"] for cat in entry.findall(f"{ATOM_NS}category") if cat.attrib.get("term")
    ]

    return ArxivPaper(
        arxiv_id=arxiv_id,
        title=title,
        authors=authors,
        abstract=abstract,
        published=published,
        url=url_link,
        categories=categories,
    )


def _text(element: ET.Element, tag: str) -> str:
    found = element.find(tag)
    if found is None or found.text is None:
        return ""
    return found.text


def _strip_arxiv_id(raw: str) -> str:
    """``http://arxiv.org/abs/2401.12345v1`` → ``2401.12345v1``."""
    return raw.rsplit("/", 1)[-1].strip()
