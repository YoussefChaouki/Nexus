"""Benchmark architectures for the NEXUS evaluation harness.

Each entry pairs a realistic AI-system description with the OWASP LLM
Top 10 categories and threat surfaces a competent auditor is expected to
surface. ``expected_owasp`` / ``expected_surfaces`` are the ground truth
the harness scores coverage against — keep them conservative (only the
threats that are unambiguous for the described architecture) so coverage
numbers stay honest.

These are modelled as Pydantic objects rather than the bare dicts shown
in the sprint brief, to stay aligned with the project-wide "Pydantic v2
for every data model" rule and keep ``mypy --strict`` clean.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Architecture(BaseModel):
    """A single benchmark target with its expected-coverage ground truth."""

    id: str
    description: str
    expected_surfaces: list[str] = Field(min_length=1)
    expected_owasp: list[str] = Field(min_length=1)


ARCHITECTURES: list[Architecture] = [
    Architecture(
        id="rag_basic",
        description=("FastAPI + pgvector RAG, OpenAI API, no authentication, public internet"),
        expected_surfaces=["prompt_injection", "data_leakage", "supply_chain"],
        expected_owasp=["LLM01", "LLM06", "LLM05"],
    ),
    Architecture(
        id="rag_enterprise",
        description=(
            "LangChain RAG with Azure OpenAI, MSAL auth, private VPC, SharePoint ingestion"
        ),
        expected_surfaces=[
            "prompt_injection",
            "model_denial_of_service",
            "insecure_plugin",
        ],
        expected_owasp=["LLM01", "LLM04", "LLM07"],
    ),
    Architecture(
        id="autonomous_agent",
        description=(
            "Autonomous LLM agent with code execution, web browsing, email "
            "sending, no human-in-the-loop"
        ),
        expected_surfaces=["excessive_agency", "prompt_injection", "data_leakage"],
        expected_owasp=["LLM08", "LLM01", "LLM02"],
    ),
    Architecture(
        id="llm_api_service",
        description=(
            "Public API exposing GPT-4 with user prompt injection, no rate "
            "limiting, logs stored in S3"
        ),
        expected_surfaces=["prompt_injection", "denial_of_service", "data_leakage"],
        expected_owasp=["LLM01", "LLM04", "LLM06"],
    ),
    Architecture(
        id="ml_pipeline",
        description=(
            "MLflow training pipeline with public S3 model artifacts, "
            "community contributors, CI/CD auto-deploy"
        ),
        expected_surfaces=[
            "supply_chain",
            "model_extraction",
            "training_data_poisoning",
        ],
        expected_owasp=["LLM03", "LLM05", "LLM10"],
    ),
]
