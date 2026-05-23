"""Quick severity-distribution check for S8.T1 calibration.

Runs the full NEXUS pipeline against a handful of targets and prints
the resulting severity distribution per run + aggregate. Not the real
eval harness (that's S9.T1) — just a smoke check to confirm the
recalibrated Analyst no longer produces flat-HIGH outputs.

Usage:
    python -m scripts.quick_severity_eval               # 4 default targets
    python -m scripts.quick_severity_eval --target "..."  # one custom target

Requires a live OPENAI_API_KEY and Postgres + Redis up (``make docker-up``).
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter

from nexus.graph.graph import run_pipeline
from nexus.schemas.models import ThreatReport

DEFAULT_TARGETS: list[str] = [
    # The S7-failing target — flat HIGH before calibration.
    "FastAPI backend with pgvector for a RAG pipeline, Streamlit frontend on "
    "AWS ECS, OpenAI GPT-4, no authentication, enterprise documents ingested "
    "via user upload",
    # Hardened enterprise RAG — expect mostly MEDIUM.
    "LangChain RAG with Azure OpenAI, MSAL auth, private VPC, SharePoint "
    "ingestion, content filters enabled",
    # Autonomous agent with tools — expect at least one CRITICAL.
    "Autonomous LLM agent with code execution, web browsing, email sending, "
    "no human-in-the-loop, OpenAI API",
    # Internal-only summariser — expect MEDIUM/LOW dominant.
    "Internal-only summarisation service behind SSO, logs scrubbed before storage, no tool calling",
]


def _format_distribution(report: ThreatReport) -> str:
    counts = Counter(s.severity.value for s in report.threat_surfaces)
    ordered = ["critical", "high", "medium", "low"]
    parts = [f"{b}={counts.get(b, 0)}" for b in ordered]
    return " | ".join(parts)


async def _run_one(target: str) -> ThreatReport:
    print(f"\n>>> {target[:90]}…")
    report = await run_pipeline(target)
    print(f"    surfaces : {len(report.threat_surfaces)}")
    print(f"    severity : {_format_distribution(report)}")
    print(f"    iterations: {report.iteration_count}")
    for s in report.threat_surfaces:
        reasoning = (s.severity_reasoning or "(none)")[:80]
        print(f"      - {s.severity.value:<8} {s.name[:40]:<40} :: {reasoning}")
    return report


async def main(targets: list[str]) -> None:
    reports = [await _run_one(t) for t in targets]

    print("\n=== Aggregate ===")
    overall: Counter[str] = Counter()
    distinct_bands_per_run: list[int] = []
    for r in reports:
        c = Counter(s.severity.value for s in r.threat_surfaces)
        overall.update(c)
        distinct_bands_per_run.append(len(c))

    total_surfaces = sum(overall.values())
    print(f"total surfaces : {total_surfaces}")
    for band in ("critical", "high", "medium", "low"):
        n = overall.get(band, 0)
        pct = 100 * n / total_surfaces if total_surfaces else 0
        print(f"  {band:<8} : {n:>3}  ({pct:5.1f}%)")

    flat = sum(1 for n in distinct_bands_per_run if n == 1)
    print(f"\nruns with only 1 distinct band : {flat}/{len(reports)}  (target: 0 or close to it)")
    print(
        f"mean distinct bands per run    : "
        f"{sum(distinct_bands_per_run) / len(distinct_bands_per_run):.2f}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", action="append", help="custom target (repeatable)")
    args = parser.parse_args()
    targets = args.target if args.target else DEFAULT_TARGETS
    asyncio.run(main(targets))
