"""Tests for pattern_detector.py.

The semgrep subprocess is faked via monkeypatching
asyncio.create_subprocess_exec — no real semgrep binary required.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from pattern_detector import PatternDetectionError, run_semgrep

SEMGREP_OUTPUT: dict[str, Any] = {
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "snippet.py",
            "start": {"line": 3},
            "extra": {"message": "Detected use of eval().", "severity": "ERROR"},
        },
    ],
}


class _FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        pass


@pytest.mark.asyncio
async def test_run_semgrep_parses_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:
        return _FakeProcess(json.dumps(SEMGREP_OUTPUT).encode(), returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    findings = await run_semgrep("eval(x)", "python")

    assert len(findings) == 1
    assert findings[0].rule_id == "python.lang.security.audit.eval-detected"
    assert findings[0].line == 3
    assert findings[0].severity == "error"
    assert findings[0].path == "snippet.py"


@pytest.mark.asyncio
async def test_run_semgrep_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:
        raise FileNotFoundError("semgrep not found")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    with pytest.raises(PatternDetectionError, match="not installed"):
        await run_semgrep("x = 1", "python")


@pytest.mark.asyncio
async def test_run_semgrep_real_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:
        return _FakeProcess(b"", b"fatal error", returncode=2)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    with pytest.raises(PatternDetectionError, match="exit 2"):
        await run_semgrep("x = 1", "python")


@pytest.mark.asyncio
async def test_run_semgrep_findings_exit_code_is_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """semgrep exits 1 (not 0) whenever it has findings — must not raise."""

    async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:
        return _FakeProcess(json.dumps(SEMGREP_OUTPUT).encode(), returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    findings = await run_semgrep("eval(x)", "python")
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_run_semgrep_invalid_json_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:
        return _FakeProcess(b"not json", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    with pytest.raises(PatternDetectionError, match="invalid semgrep JSON"):
        await run_semgrep("x = 1", "python")
