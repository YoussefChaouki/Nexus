"""Parse the MITRE ATLAS STIX 2.1 bundle into :class:`ATLASTechnique` models.

The bundle (``ATLAS.json``) contains a list of STIX domain objects. This
loader extracts ``attack-pattern`` objects and resolves their relationships
to ``course-of-action`` (mitigations) and ATLAS-specific case-study
objects when present. Unknown fields are tolerated — the loader degrades
gracefully on minor schema changes.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

import structlog
from schemas import ATLASTechnique

logger = structlog.get_logger(__name__)

_ATLAS_SOURCE_NAME: Final[str] = "mitre-atlas"
_ATLAS_KILL_CHAIN_NAME: Final[str] = "mitre-atlas"


class STIXLoadError(Exception):
    """Raised when the STIX bundle cannot be read or parsed."""


def load_atlas_techniques(stix_path: str | Path) -> list[ATLASTechnique]:
    """Read ``stix_path`` and return one :class:`ATLASTechnique` per attack-pattern.

    Args:
        stix_path: Filesystem path to ``ATLAS.json``.

    Raises:
        STIXLoadError: If the file is missing, not JSON, or not a STIX bundle.
    """
    path = Path(stix_path)
    if not path.is_file():
        raise STIXLoadError(f"ATLAS STIX bundle not found at {path}")

    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise STIXLoadError(f"failed to read ATLAS STIX bundle: {exc}") from exc

    return parse_atlas_bundle(bundle)


def parse_atlas_bundle(bundle: Any) -> list[ATLASTechnique]:
    """Parse an in-memory STIX bundle dict into ATLAS techniques.

    Useful for tests that build a bundle inline without writing to disk.
    """
    if not isinstance(bundle, dict):
        raise STIXLoadError("STIX bundle must be a JSON object")

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise STIXLoadError("STIX bundle 'objects' must be a list")

    course_of_action_names = _index_names(objects, "course-of-action")
    case_study_names = _index_names(objects, "x-mitre-case-study")
    related_ids = _related_ids_by_attack_pattern(objects)

    techniques: list[ATLASTechnique] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        technique = _attack_pattern_to_technique(
            obj,
            course_of_action_names=course_of_action_names,
            case_study_names=case_study_names,
            related_ids=related_ids,
        )
        if technique is not None:
            techniques.append(technique)
    return techniques


def _attack_pattern_to_technique(
    obj: dict[str, Any],
    *,
    course_of_action_names: dict[str, str],
    case_study_names: dict[str, str],
    related_ids: dict[str, set[str]],
) -> ATLASTechnique | None:
    technique_id, url = _atlas_external_ref(obj.get("external_references"))
    if not technique_id:
        logger.debug("skipping_attack_pattern_without_atlas_id", id=obj.get("id"))
        return None

    name = str(obj.get("name", "")).strip()
    description = str(obj.get("description", "")).strip()
    tactic = _tactic(obj.get("kill_chain_phases"))
    subtechniques = _subtechniques(
        obj.get("x_mitre_subtechniques") or obj.get("subtechniques"),
    )

    stix_id = str(obj.get("id", ""))
    related = related_ids.get(stix_id, set())
    mitigations = sorted(
        {course_of_action_names[r] for r in related if r in course_of_action_names},
    )
    case_studies = sorted(
        {case_study_names[r] for r in related if r in case_study_names},
    )

    return ATLASTechnique(
        technique_id=technique_id,
        name=name,
        description=description,
        tactic=tactic,
        subtechniques=subtechniques,
        case_studies=case_studies,
        mitigations=mitigations,
        url=url,
    )


def _atlas_external_ref(refs: Any) -> tuple[str, str]:
    """Return ``(technique_id, url)`` from the mitre-atlas external reference."""
    if not isinstance(refs, list):
        return ("", "")
    for ref in refs:
        if (
            isinstance(ref, dict)
            and ref.get("source_name") == _ATLAS_SOURCE_NAME
            and isinstance(ref.get("external_id"), str)
        ):
            url = ref.get("url")
            return (ref["external_id"], str(url) if isinstance(url, str) else "")
    return ("", "")


def _tactic(phases: Any) -> str:
    """Join ATLAS kill-chain phase names into a single tactic string."""
    if not isinstance(phases, list):
        return ""
    names: list[str] = []
    for phase in phases:
        if (
            isinstance(phase, dict)
            and phase.get("kill_chain_name") == _ATLAS_KILL_CHAIN_NAME
            and isinstance(phase.get("phase_name"), str)
        ):
            names.append(phase["phase_name"])
    return ", ".join(names)


def _subtechniques(value: Any) -> list[str]:
    """Coerce a subtechnique list to a list of identifier strings."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for key in ("technique_id", "external_id", "id"):
                v = item.get(key)
                if isinstance(v, str):
                    out.append(v)
                    break
    return out


def _index_names(objects: Iterable[Any], stix_type: str) -> dict[str, str]:
    """Map STIX object id → display name for a given type."""
    out: dict[str, str] = {}
    for obj in objects:
        if (
            isinstance(obj, dict)
            and obj.get("type") == stix_type
            and isinstance(obj.get("id"), str)
            and isinstance(obj.get("name"), str)
        ):
            out[obj["id"]] = obj["name"]
    return out


def _related_ids_by_attack_pattern(
    objects: Iterable[Any],
) -> dict[str, set[str]]:
    """For each ``attack-pattern`` STIX id, the STIX ids related via any relationship.

    The lookup is direction-agnostic: whether the attack-pattern is the
    relationship's ``source_ref`` or ``target_ref``, the *other* end is
    registered against it. This handles both the ATLAS conventions
    (``mitigates``: course-of-action → attack-pattern; ``uses``:
    case-study → attack-pattern) and any inverted variants without
    coupling to a fixed relationship type.
    """
    out: dict[str, set[str]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        source = obj.get("source_ref")
        target = obj.get("target_ref")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if source.startswith("attack-pattern--"):
            out.setdefault(source, set()).add(target)
        if target.startswith("attack-pattern--"):
            out.setdefault(target, set()).add(source)
    return out
