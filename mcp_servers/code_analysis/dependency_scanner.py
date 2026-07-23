"""Dependency CVE scanning: parse a manifest, look each package up on NVD.

Supports ``requirements.txt`` and ``pyproject.toml`` content. Detection is by
attempted TOML parse (pyproject) with a fallback to line-based requirements
parsing — good enough for the two formats this tool targets.

The NVD lookup is a deliberately small, self-contained client (rate-limited
keyword search only) rather than a reuse of ``mcp_servers/nvd/client.py`` —
each MCP server here is a standalone package with its own ``pyproject.toml``
and no cross-package imports.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import tomllib
from typing import Any, Final

import httpx
import structlog
from schemas import CVEEntry, DependencyFinding

logger = structlog.get_logger(__name__)

NVD_BASE_URL: Final[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_NO_KEY: Final[float] = 5.0
RATE_LIMIT_WITH_KEY: Final[float] = 50.0
DEFAULT_MAX_CVES_PER_PACKAGE: Final[int] = 3

_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.\-*]+)?"
)


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------


def parse_requirements(content: str) -> list[tuple[str, str | None]]:
    """Parse a ``requirements.txt``-style file into ``(package, version)`` pairs."""
    deps: list[tuple[str, str | None]] = []
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _REQUIREMENT_RE.match(line)
        if not match:
            continue
        deps.append((match.group(1), match.group(2)))
    return deps


def _split_spec(spec: str) -> tuple[str, str | None]:
    match = _REQUIREMENT_RE.match(spec.strip())
    if not match:
        return spec.strip(), None
    return match.group(1), match.group(2)


def parse_pyproject(content: str) -> list[tuple[str, str | None]]:
    """Parse ``[project.dependencies]`` and optional-dependency groups."""
    data = tomllib.loads(content)
    project = data.get("project", {})
    raw_specs: list[str] = list(project.get("dependencies", []) or [])
    for group in (project.get("optional-dependencies", {}) or {}).values():
        raw_specs.extend(group or [])
    return [_split_spec(spec) for spec in raw_specs]


def parse_dependencies(content: str) -> list[tuple[str, str | None]]:
    """Parse either manifest format, detected by attempting a TOML load first."""
    try:
        return parse_pyproject(content)
    except tomllib.TOMLDecodeError:
        return parse_requirements(content)


# ---------------------------------------------------------------------------
# Minimal NVD lookup
# ---------------------------------------------------------------------------


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


def _one_cve(cve: dict[str, Any]) -> CVEEntry:
    description = ""
    for item in cve.get("descriptions", []) or []:
        if isinstance(item, dict) and item.get("lang") == "en":
            description = str(item.get("value", ""))
            break
    severity: str | None = None
    score: float | None = None
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key)
        if not isinstance(rows, list) or not rows:
            continue
        cvss_data = rows[0].get("cvssData", {}) if isinstance(rows[0], dict) else {}
        raw_score = cvss_data.get("baseScore")
        score = float(raw_score) if isinstance(raw_score, int | float) else None
        raw_severity = cvss_data.get("baseSeverity")
        severity = str(raw_severity) if raw_severity else None
        break
    return CVEEntry(
        cve_id=str(cve.get("id", "")),
        description=description,
        severity=severity,
        cvss_score=score,
    )


def _parse_cves(data: dict[str, Any]) -> list[CVEEntry]:
    items = data.get("vulnerabilities", [])
    if not isinstance(items, list):
        return []
    return [
        _one_cve(item["cve"])
        for item in items
        if isinstance(item, dict) and isinstance(item.get("cve"), dict)
    ]


async def _search_nvd_for_package(
    client: httpx.AsyncClient,
    package: str,
    *,
    api_key: str | None,
    limiter: _RateLimiter,
    max_results: int,
) -> list[CVEEntry]:
    await limiter.acquire()
    headers = {"apiKey": api_key} if api_key else {}
    response = await client.get(
        NVD_BASE_URL,
        params={"keywordSearch": package, "resultsPerPage": str(max_results)},
        headers=headers,
    )
    if response.status_code != 200:
        return []
    data = response.json()
    if not isinstance(data, dict):
        return []
    return _parse_cves(data)


async def scan_dependencies(
    content: str,
    *,
    client: httpx.AsyncClient | None = None,
    max_cves_per_package: int = DEFAULT_MAX_CVES_PER_PACKAGE,
) -> list[DependencyFinding]:
    """Parse ``content`` as a manifest and look each dependency up on NVD.

    A failed lookup for one package (network error, bad JSON) is logged and
    skipped — never aborts the whole scan.
    """
    deps = parse_dependencies(content)
    api_key = os.environ.get("NVD_API_KEY")
    rate = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_NO_KEY
    limiter = _RateLimiter(1.0 / rate)
    owns_client = client is None
    http_client = client or httpx.AsyncClient(timeout=30.0)

    findings: list[DependencyFinding] = []
    try:
        for name, version in deps:
            try:
                cves = await _search_nvd_for_package(
                    http_client,
                    name,
                    api_key=api_key,
                    limiter=limiter,
                    max_results=max_cves_per_package,
                )
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("nvd_lookup_failed", package=name, error=str(exc))
                cves = []
            findings.append(DependencyFinding(package=name, version=version, cves=cves))
    finally:
        if owns_client:
            await http_client.aclose()
    return findings
