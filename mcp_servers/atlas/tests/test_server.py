"""Tests for the MITRE ATLAS MCP server.

Uses a hand-built minimal STIX bundle (3 techniques, 1 mitigation, 1
case study) plus a deterministic embed function so we never call
OpenAI or read a real ATLAS.json.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from schemas import ATLASTechnique, MCPToolError
from server import get_technique_detail, search_by_tactic, search_techniques, set_search
from stix_loader import STIXLoadError, parse_atlas_bundle
from vector_search import ATLASVectorSearch

# --- Fixtures -------------------------------------------------------------


def _attack_pattern(
    stix_id: str,
    name: str,
    description: str,
    technique_id: str,
    tactic: str,
) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": description,
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-atlas", "phase_name": tactic},
        ],
        "external_references": [
            {
                "source_name": "mitre-atlas",
                "external_id": technique_id,
                "url": f"https://atlas.mitre.org/techniques/{technique_id}",
            },
        ],
    }


def _bundle() -> dict[str, Any]:
    pattern_a = _attack_pattern(
        "attack-pattern--aaaa",
        "Prompt Injection",
        "Adversaries may craft inputs that override system instructions in an LLM.",
        "AML.T0051",
        "ml-attack-staging",
    )
    pattern_b = _attack_pattern(
        "attack-pattern--bbbb",
        "Discover ML Model Family",
        "Adversaries may identify the family or vendor of a deployed model.",
        "AML.T0014",
        "reconnaissance",
    )
    pattern_c = _attack_pattern(
        "attack-pattern--cccc",
        "Evade ML Model",
        "Adversaries craft inputs to bypass an ML classifier.",
        "AML.T0015",
        "ml-attack-staging",
    )
    mitigation = {
        "type": "course-of-action",
        "id": "course-of-action--m1",
        "name": "Input validation",
    }
    case_study = {
        "type": "x-mitre-case-study",
        "id": "x-mitre-case-study--cs1",
        "name": "Bing Chat jailbreak (2023)",
    }
    relationship = {
        "type": "relationship",
        "id": "relationship--r1",
        "relationship_type": "mitigates",
        "source_ref": "course-of-action--m1",
        "target_ref": "attack-pattern--aaaa",
    }
    case_study_link = {
        "type": "relationship",
        "id": "relationship--r2",
        "relationship_type": "uses",
        "source_ref": "attack-pattern--aaaa",
        "target_ref": "x-mitre-case-study--cs1",
    }
    return {
        "type": "bundle",
        "id": "bundle--xxxx",
        "objects": [
            pattern_a,
            pattern_b,
            pattern_c,
            mitigation,
            case_study,
            relationship,
            case_study_link,
        ],
    }


def _fake_embed_fn() -> Any:
    """Deterministic embed: each text gets a 4-d one-hot-ish vector keyed by content."""

    async def embed(texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for t in texts:
            lower = t.lower()
            vec = [
                1.0 if "prompt" in lower or "inject" in lower else 0.0,
                1.0 if "model family" in lower or "discover" in lower else 0.0,
                1.0 if "evade" in lower or "classifier" in lower or "bypass" in lower else 0.0,
                0.1,  # constant noise so vectors aren't zero
            ]
            vectors.append(vec)
        return vectors

    return embed


@pytest.fixture()
async def vector_search() -> AsyncIterator[ATLASVectorSearch]:
    techniques = parse_atlas_bundle(_bundle())
    search = ATLASVectorSearch(techniques, embed_fn=_fake_embed_fn())
    set_search(search)
    try:
        yield search
    finally:
        set_search(None)


# --- stix_loader ---------------------------------------------------------


def test_parse_bundle_extracts_three_techniques() -> None:
    techniques = parse_atlas_bundle(_bundle())
    ids = sorted(t.technique_id for t in techniques)
    assert ids == ["AML.T0014", "AML.T0015", "AML.T0051"]


def test_parse_bundle_resolves_mitigations_and_case_studies() -> None:
    techniques = parse_atlas_bundle(_bundle())
    by_id = {t.technique_id: t for t in techniques}
    assert by_id["AML.T0051"].mitigations == ["Input validation"]
    assert by_id["AML.T0051"].case_studies == ["Bing Chat jailbreak (2023)"]
    assert by_id["AML.T0014"].mitigations == []


def test_parse_bundle_skips_attack_patterns_without_atlas_id() -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--no-atlas-ref",
                "name": "Generic ATT&CK technique",
                "description": "...",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"},
                ],
            },
        ],
    }
    assert parse_atlas_bundle(bundle) == []


def test_parse_bundle_rejects_non_object_input() -> None:
    with pytest.raises(STIXLoadError):
        parse_atlas_bundle([])


# --- search_techniques ---------------------------------------------------


async def test_search_techniques_returns_relevant_first(
    vector_search: ATLASVectorSearch,
) -> None:
    raw = await search_techniques(query="prompt injection attack", max_results=2)

    parsed = json.loads(raw)
    techniques = [ATLASTechnique.model_validate(item) for item in parsed]
    assert techniques[0].technique_id == "AML.T0051"
    assert len(techniques) == 2


async def test_search_techniques_caps_at_max_results(
    vector_search: ATLASVectorSearch,
) -> None:
    raw = await search_techniques(query="evade classifier", max_results=1)

    parsed = json.loads(raw)
    assert len(parsed) == 1
    assert parsed[0]["technique_id"] == "AML.T0015"


async def test_search_techniques_returns_error_when_stix_missing() -> None:
    set_search(None)  # force re-load on next access
    raw = await search_techniques(query="x", max_results=1)

    err = MCPToolError.model_validate_json(raw)
    assert err.error_type in {"atlas_stix_unavailable", "internal_error"}
    assert err.retryable is False


# --- get_technique_detail ------------------------------------------------


async def test_get_technique_detail_valid_id(
    vector_search: ATLASVectorSearch,
) -> None:
    raw = await get_technique_detail(technique_id="AML.T0051")
    technique = ATLASTechnique.model_validate_json(raw)
    assert technique.name == "Prompt Injection"
    assert technique.url.endswith("/AML.T0051")


async def test_get_technique_detail_unknown_id_returns_error(
    vector_search: ATLASVectorSearch,
) -> None:
    raw = await get_technique_detail(technique_id="AML.T9999")
    err = MCPToolError.model_validate_json(raw)
    assert err.error_type == "not_found"
    assert "AML.T9999" in err.error
    assert err.retryable is False


# --- search_by_tactic ----------------------------------------------------


async def test_search_by_tactic_filters_correctly(
    vector_search: ATLASVectorSearch,
) -> None:
    raw = await search_by_tactic(tactic_name="ml-attack-staging")
    parsed = json.loads(raw)
    ids = sorted(item["technique_id"] for item in parsed)
    assert ids == ["AML.T0015", "AML.T0051"]


async def test_search_by_tactic_unknown_returns_empty(
    vector_search: ATLASVectorSearch,
) -> None:
    raw = await search_by_tactic(tactic_name="exfiltration")
    assert json.loads(raw) == []


async def test_search_by_tactic_is_case_insensitive(
    vector_search: ATLASVectorSearch,
) -> None:
    raw = await search_by_tactic(tactic_name="RECONNAISSANCE")
    parsed = json.loads(raw)
    assert len(parsed) == 1
    assert parsed[0]["technique_id"] == "AML.T0014"
