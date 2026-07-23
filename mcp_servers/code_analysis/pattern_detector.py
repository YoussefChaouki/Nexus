"""Semgrep-backed pattern detection over a code snippet.

Writes ``code_content`` to a temp file with an extension matching
``language``, runs semgrep against it, and maps the JSON results into
:class:`PatternFinding` objects. Requires the ``semgrep`` binary on
``PATH`` (installed in the container image, not a Python dependency).
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any, Final

import structlog
from schemas import PatternFinding

logger = structlog.get_logger(__name__)

DEFAULT_TIMEOUT_SECONDS: Final[float] = 60.0
_EXTENSION_BY_LANGUAGE: Final[dict[str, str]] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "java": ".java",
    "ruby": ".rb",
    "yaml": ".yaml",
}
# semgrep exit codes: 0 = clean, 1 = findings present, >=2 = real failure.
_SEMGREP_FAILURE_EXIT_CODE: Final[int] = 2


class PatternDetectionError(Exception):
    """Raised when semgrep is unavailable, times out, or fails to run."""


async def run_semgrep(
    code_content: str,
    language: str = "python",
    *,
    config: str = "auto",
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[PatternFinding]:
    """Run semgrep against ``code_content`` and return its findings.

    Args:
        code_content: Raw source to scan (written to a temp file — semgrep
            operates on files, not stdin).
        language: Selects the temp file extension so semgrep's language
            auto-detection picks the right analyzers.
        config: Semgrep ruleset; ``"auto"`` pulls the registry's default
            rules (includes OWASP-tagged rules) for the detected language.
        timeout_seconds: Hard cap on the subprocess run.

    Raises:
        PatternDetectionError: semgrep is not installed, times out, or
            emits output that isn't valid semgrep JSON.
    """
    suffix = _EXTENSION_BY_LANGUAGE.get(language.lower(), ".txt")
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = Path(tmp_dir) / f"snippet{suffix}"
        file_path.write_text(code_content, encoding="utf-8")

        try:
            process = await asyncio.create_subprocess_exec(
                "semgrep",
                "--config",
                config,
                "--json",
                "--quiet",
                str(file_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise PatternDetectionError("semgrep is not installed") from exc

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError as exc:
            process.kill()
            raise PatternDetectionError(f"semgrep timed out after {timeout_seconds}s") from exc

        if process.returncode is not None and process.returncode >= _SEMGREP_FAILURE_EXIT_CODE:
            raise PatternDetectionError(
                f"semgrep failed (exit {process.returncode}): "
                f"{stderr.decode(errors='replace').strip()}"
            )

        try:
            payload = json.loads(stdout.decode(errors="replace") or "{}")
        except json.JSONDecodeError as exc:
            raise PatternDetectionError(f"invalid semgrep JSON: {exc}") from exc

    results = payload.get("results", [])
    if not isinstance(results, list):
        return []
    return [_to_finding(item) for item in results if isinstance(item, dict)]


def _to_finding(item: dict[str, Any]) -> PatternFinding:
    extra = item.get("extra", {}) if isinstance(item.get("extra"), dict) else {}
    start = item.get("start", {}) if isinstance(item.get("start"), dict) else {}
    return PatternFinding(
        rule_id=str(item.get("check_id", "unknown")),
        message=str(extra.get("message", "")),
        line=int(start.get("line", 0) or 0),
        severity=str(extra.get("severity", "info")).lower(),
        path=str(item["path"]) if item.get("path") else None,
    )
