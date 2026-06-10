"""Compare NEXUS multi-agent coverage against a single-prompt baseline.

Runs both strategies over every benchmark architecture, prints a
comparison table, and writes ``docs/EVAL_RESULTS.md``. This is the
script behind the README metrics — run it with a live model:

    python -m scripts.compare_baseline            # real LLM (default)
    python -m scripts.compare_baseline --mock     # offline, no API key

Real mode needs ``OPENAI_API_KEY`` and Postgres + Redis up
(``make docker-up``). Mock mode uses the deterministic eval fakes and is
what CI exercises via ``tests/eval/test_harness.py``.
"""

# ruff: noqa: T201 — print() is the intended output channel for this CLI.

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
from pathlib import Path

from tests.eval.architectures import ARCHITECTURES, Architecture
from tests.eval.harness import (
    CoverageResult,
    _run_nexus,
    _score_nexus,
    run_single_prompt_baseline,
)

EVAL_RESULTS_PATH = Path(__file__).resolve().parent.parent / "docs" / "EVAL_RESULTS.md"


async def _nexus_result(arch: Architecture, *, use_real_llm: bool) -> CoverageResult:
    import time

    start = time.perf_counter()
    report = await _run_nexus(arch, use_real_llm=use_real_llm)
    latency = time.perf_counter() - start
    return _score_nexus(arch, report, latency)


async def _baseline_result(arch: Architecture, *, use_mock: bool) -> CoverageResult:
    if use_mock:
        from tests.eval.fakes import baseline_mock_llm

        return await run_single_prompt_baseline(arch, llm=baseline_mock_llm())
    return await run_single_prompt_baseline(arch)


def _pct(value: float) -> str:
    return f"{value * 100:5.1f}%"


def _render_table(rows: list[tuple[CoverageResult, CoverageResult]]) -> str:
    lines = [
        "| Architecture | NEXUS OWASP% | Baseline OWASP% | Δ OWASP | "
        "NEXUS Surface% | Baseline Surface% | Δ Surface |",
        "|---|---|---|---|---|---|---|",
    ]
    for nexus, base in rows:
        d_owasp = nexus.owasp_coverage - base.owasp_coverage
        d_surface = nexus.surface_coverage - base.surface_coverage
        lines.append(
            f"| `{nexus.architecture_id}` | {_pct(nexus.owasp_coverage)} | "
            f"{_pct(base.owasp_coverage)} | {d_owasp * 100:+5.1f} | "
            f"{_pct(nexus.surface_coverage)} | {_pct(base.surface_coverage)} | "
            f"{d_surface * 100:+5.1f} |"
        )
    return "\n".join(lines)


def _render_markdown(
    rows: list[tuple[CoverageResult, CoverageResult]], *, used_real_llm: bool
) -> str:
    n = len(rows) or 1
    nexus_owasp = sum(r[0].owasp_coverage for r in rows) / n
    base_owasp = sum(r[1].owasp_coverage for r in rows) / n
    nexus_surface = sum(r[0].surface_coverage for r in rows) / n
    base_surface = sum(r[1].surface_coverage for r in rows) / n
    mode = "live LLM" if used_real_llm else "offline mock (deterministic)"
    return (
        "# NEXUS Evaluation Results\n\n"
        f"_Generated {datetime.now(UTC).isoformat(timespec='seconds')} "
        f"— mode: {mode}._\n\n"
        "Multi-agent NEXUS vs. a single-prompt baseline across "
        f"{len(rows)} benchmark architectures. Coverage = fraction of the "
        "expected OWASP LLM Top 10 categories / threat surfaces found.\n\n"
        f"{_render_table(rows)}\n\n"
        "## Aggregate\n\n"
        "| Metric | NEXUS | Baseline | Delta |\n"
        "|---|---|---|---|\n"
        f"| Mean OWASP coverage | {_pct(nexus_owasp)} | {_pct(base_owasp)} | "
        f"{(nexus_owasp - base_owasp) * 100:+.1f} |\n"
        f"| Mean surface coverage | {_pct(nexus_surface)} | {_pct(base_surface)} | "
        f"{(nexus_surface - base_surface) * 100:+.1f} |\n"
    )


def _write_markdown(markdown: str) -> None:
    """Sync helper: keeps file IO out of the async ``main`` scope (ASYNC240)."""
    EVAL_RESULTS_PATH.write_text(markdown, encoding="utf-8")


async def main(*, use_mock: bool) -> None:
    use_real_llm = not use_mock
    rows: list[tuple[CoverageResult, CoverageResult]] = []
    for arch in ARCHITECTURES:
        print(f">>> {arch.id}: {arch.description[:70]}…")
        nexus = await _nexus_result(arch, use_real_llm=use_real_llm)
        base = await _baseline_result(arch, use_mock=use_mock)
        rows.append((nexus, base))
        print(
            f"    NEXUS  owasp={_pct(nexus.owasp_coverage)} "
            f"surface={_pct(nexus.surface_coverage)} "
            f"(surfaces={nexus.surface_count}, iters={nexus.iteration_count})"
        )
        print(f"    base   owasp={_pct(base.owasp_coverage)} surface={_pct(base.surface_coverage)}")

    print("\n" + _render_table(rows))
    markdown = _render_markdown(rows, used_real_llm=use_real_llm)
    _write_markdown(markdown)
    print(f"\nWrote {EVAL_RESULTS_PATH}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use deterministic offline fakes instead of a live LLM.",
    )
    args = parser.parse_args()
    asyncio.run(main(use_mock=args.mock))
