"""Attack-surface extraction from infra/config files.

Supports four ``config_type`` values: ``docker-compose``, ``kubernetes``,
``openapi``, ``terraform``. Docker Compose, Kubernetes and OpenAPI are
parsed as YAML/JSON; Terraform HCL is scanned with targeted regexes rather
than a full HCL parser (keeps this package dependency-light — good enough
to catch the two canonical misconfigurations: open security groups and
public S3 buckets).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any, Final

import yaml
from schemas import AttackSurfaceIssue, AttackSurfaceSummary

_SECRET_ENV_RE = re.compile(r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY)", re.IGNORECASE)
_HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head"}
)
_OPEN_CIDR_RE = re.compile(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"[^\]]*\]')
_PUBLIC_ACL_RE = re.compile(r'acl\s*=\s*"(public-read(?:-write)?)"')
_PUBLIC_ACCESS_BLOCK_RE = re.compile(
    r"(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)"
    r"\s*=\s*false"
)


class AttackSurfaceParseError(Exception):
    """Raised when ``config_content`` cannot be parsed for the given type."""


# ---------------------------------------------------------------------------
# docker-compose
# ---------------------------------------------------------------------------


def _iter_env_pairs(env: Any) -> list[tuple[str, str]]:
    if isinstance(env, dict):
        return [(str(k), str(v)) for k, v in env.items() if v is not None]
    if isinstance(env, list):
        pairs = []
        for item in env:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                pairs.append((key, value))
        return pairs
    return []


def _looks_like_reference(value: str) -> bool:
    stripped = value.strip()
    return not stripped or stripped.startswith("$")


def _docker_compose_issues(content: str) -> list[AttackSurfaceIssue]:
    try:
        data = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        raise AttackSurfaceParseError(f"invalid docker-compose YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise AttackSurfaceParseError("docker-compose document must be a YAML mapping")

    issues: list[AttackSurfaceIssue] = []
    services = data.get("services", {})
    if not isinstance(services, dict):
        return issues

    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        for port in svc.get("ports", []) or []:
            issues.append(
                AttackSurfaceIssue(
                    category="exposed_port",
                    severity="medium",
                    description=f"Service '{name}' publishes port {port} to the host",
                    location=f"services.{name}.ports",
                )
            )

        if svc.get("privileged") is True:
            issues.append(
                AttackSurfaceIssue(
                    category="privileged_container",
                    severity="high",
                    description=f"Service '{name}' runs with privileged: true",
                    location=f"services.{name}.privileged",
                )
            )

        if svc.get("network_mode") == "host":
            issues.append(
                AttackSurfaceIssue(
                    category="host_network",
                    severity="high",
                    description=f"Service '{name}' uses network_mode: host",
                    location=f"services.{name}.network_mode",
                )
            )

        for key, value in _iter_env_pairs(svc.get("environment")):
            if _SECRET_ENV_RE.search(key) and not _looks_like_reference(value):
                issues.append(
                    AttackSurfaceIssue(
                        category="hardcoded_secret",
                        severity="high",
                        description=(
                            f"Service '{name}' hardcodes '{key}' instead of "
                            "referencing a secret store or env-file"
                        ),
                        location=f"services.{name}.environment.{key}",
                    )
                )

    return issues


# ---------------------------------------------------------------------------
# kubernetes
# ---------------------------------------------------------------------------


def _pod_spec(resource_spec: Any) -> dict[str, Any]:
    """Return the PodSpec, unwrapping Deployment/StatefulSet/DaemonSet nesting."""
    if not isinstance(resource_spec, dict):
        return {}
    template = resource_spec.get("template")
    if isinstance(template, dict) and isinstance(template.get("spec"), dict):
        return template["spec"]  # type: ignore[no-any-return]
    return resource_spec


def _kubernetes_issues(content: str) -> list[AttackSurfaceIssue]:
    try:
        documents = [doc for doc in yaml.safe_load_all(content) if doc]
    except yaml.YAMLError as exc:
        raise AttackSurfaceParseError(f"invalid kubernetes YAML: {exc}") from exc

    issues: list[AttackSurfaceIssue] = []
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        kind = str(doc.get("kind", "Resource"))
        pod_spec = _pod_spec(doc.get("spec", {}))

        if pod_spec.get("hostNetwork") is True:
            issues.append(
                AttackSurfaceIssue(
                    category="host_network",
                    severity="high",
                    description=f"{kind} sets hostNetwork: true",
                    location=f"{kind}.spec.hostNetwork",
                )
            )

        for container in pod_spec.get("containers", []) or []:
            if not isinstance(container, dict):
                continue
            cname = str(container.get("name", "container"))
            security_context = container.get("securityContext", {}) or {}

            if security_context.get("privileged") is True:
                issues.append(
                    AttackSurfaceIssue(
                        category="privileged_container",
                        severity="critical",
                        description=f"Container '{cname}' runs with securityContext.privileged: true",
                        location=f"{kind}.{cname}.securityContext.privileged",
                    )
                )
            if security_context.get("runAsUser") == 0:
                issues.append(
                    AttackSurfaceIssue(
                        category="runs_as_root",
                        severity="high",
                        description=f"Container '{cname}' explicitly sets runAsUser: 0",
                        location=f"{kind}.{cname}.securityContext.runAsUser",
                    )
                )
            resources = container.get("resources", {}) or {}
            if not resources.get("limits"):
                issues.append(
                    AttackSurfaceIssue(
                        category="no_resource_limits",
                        severity="low",
                        description=f"Container '{cname}' has no resource limits set",
                        location=f"{kind}.{cname}.resources.limits",
                    )
                )

    return issues


# ---------------------------------------------------------------------------
# openapi
# ---------------------------------------------------------------------------


def _openapi_issues(content: str) -> list[AttackSurfaceIssue]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise AttackSurfaceParseError(f"invalid OpenAPI document: {exc}") from exc

    if not isinstance(data, dict):
        raise AttackSurfaceParseError("OpenAPI document must be a JSON/YAML object")

    global_security = data.get("security")
    paths = data.get("paths", {})
    if not isinstance(paths, dict):
        return []

    issues: list[AttackSurfaceIssue] = []
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            operation_security = operation.get("security", global_security)
            if not operation_security:
                issues.append(
                    AttackSurfaceIssue(
                        category="missing_auth",
                        severity="high",
                        description=f"{method.upper()} {path} has no security requirement",
                        location=f"paths.{path}.{method}",
                    )
                )
    return issues


# ---------------------------------------------------------------------------
# terraform (regex heuristics — no HCL parser dependency)
# ---------------------------------------------------------------------------


def _terraform_issues(content: str) -> list[AttackSurfaceIssue]:
    issues: list[AttackSurfaceIssue] = []
    for match in _OPEN_CIDR_RE.finditer(content):
        issues.append(
            AttackSurfaceIssue(
                category="open_security_group",
                severity="critical",
                description="Security group / firewall rule allows ingress from 0.0.0.0/0",
                location=f"offset:{match.start()}",
            )
        )
    for match in _PUBLIC_ACL_RE.finditer(content):
        issues.append(
            AttackSurfaceIssue(
                category="public_s3_bucket",
                severity="high",
                description=f"S3 bucket ACL is '{match.group(1)}'",
                location=f"offset:{match.start()}",
            )
        )
    for match in _PUBLIC_ACCESS_BLOCK_RE.finditer(content):
        issues.append(
            AttackSurfaceIssue(
                category="public_s3_bucket",
                severity="medium",
                description=f"S3 public access block setting '{match.group(1)}' is disabled",
                location=f"offset:{match.start()}",
            )
        )
    return issues


_EXTRACTORS: Final[dict[str, Callable[[str], list[AttackSurfaceIssue]]]] = {
    "docker-compose": _docker_compose_issues,
    "kubernetes": _kubernetes_issues,
    "openapi": _openapi_issues,
    "terraform": _terraform_issues,
}


def extract_attack_surface(config_content: str, config_type: str) -> AttackSurfaceSummary:
    """Extract attack-surface issues from a config file.

    Args:
        config_content: Raw file content.
        config_type: One of ``"docker-compose"``, ``"kubernetes"``,
            ``"openapi"``, ``"terraform"``.

    Raises:
        AttackSurfaceParseError: Unknown ``config_type`` or unparsable content.
    """
    extractor = _EXTRACTORS.get(config_type)
    if extractor is None:
        raise AttackSurfaceParseError(
            f"unsupported config_type '{config_type}', must be one of {sorted(_EXTRACTORS)}"
        )
    return AttackSurfaceSummary(config_type=config_type, issues=extractor(config_content))
