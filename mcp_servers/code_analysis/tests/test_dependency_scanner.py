"""Tests for dependency_scanner.py.

NVD is mocked with respx using the same response shape as the real
NVD MCP server tests.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from dependency_scanner import (
    NVD_BASE_URL,
    parse_dependencies,
    parse_pyproject,
    parse_requirements,
    scan_dependencies,
)

REQUIREMENTS_TXT = """\
# comment line
requests==2.31.0
pydantic>=2.5,<3
httpx
-e git+https://example.com/foo.git#egg=foo
numpy==1.26.0  # inline comment
"""

PYPROJECT_TOML = """\
[project]
name = "demo"
dependencies = ["requests==2.31.0", "pydantic>=2.5"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]
"""

NVD_RESPONSE: dict[str, Any] = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-0001",
                "descriptions": [{"lang": "en", "value": "A vulnerability in requests."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}},
                    ],
                },
            },
        },
    ],
}


def test_parse_requirements() -> None:
    deps = parse_requirements(REQUIREMENTS_TXT)
    names = [d[0] for d in deps]
    assert "requests" in names
    assert "httpx" in names
    assert "numpy" in names
    assert not any(n.startswith("git+") for n in names)
    versions = dict(deps)
    assert versions["requests"] == "2.31.0"


def test_parse_pyproject() -> None:
    deps = parse_pyproject(PYPROJECT_TOML)
    names = {d[0] for d in deps}
    assert names == {"requests", "pydantic", "pytest"}


def test_parse_dependencies_detects_format() -> None:
    assert {d[0] for d in parse_dependencies(PYPROJECT_TOML)} == {"requests", "pydantic", "pytest"}
    assert {d[0] for d in parse_dependencies(REQUIREMENTS_TXT)} >= {"requests", "httpx", "numpy"}


@pytest.mark.asyncio
@respx.mock
async def test_scan_dependencies_returns_cves() -> None:
    respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))

    async with httpx.AsyncClient() as client:
        findings = await scan_dependencies("requests==2.31.0", client=client)

    assert len(findings) == 1
    assert findings[0].package == "requests"
    assert findings[0].version == "2.31.0"
    assert findings[0].cves[0].cve_id == "CVE-2023-0001"
    assert findings[0].cves[0].severity == "HIGH"


@pytest.mark.asyncio
@respx.mock
async def test_scan_dependencies_skips_package_on_network_error() -> None:
    respx.get(NVD_BASE_URL).mock(side_effect=httpx.ConnectError("boom"))

    async with httpx.AsyncClient() as client:
        findings = await scan_dependencies("requests==2.31.0", client=client)

    assert len(findings) == 1
    assert findings[0].cves == []
