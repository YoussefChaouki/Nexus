"""Tests for attack_surface.py."""

from __future__ import annotations

import pytest
from attack_surface import AttackSurfaceParseError, extract_attack_surface

DOCKER_COMPOSE = """\
services:
  web:
    image: myapp:latest
    ports:
      - "0.0.0.0:8000:8000"
    privileged: true
    environment:
      DB_PASSWORD: "hardcoded-secret"
      API_URL: "https://example.com"
  db:
    image: postgres:16
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
"""

KUBERNETES_MANIFEST = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: demo:latest
          securityContext:
            privileged: true
            runAsUser: 0
"""

OPENAPI_DOC = """\
{
  "openapi": "3.0.0",
  "paths": {
    "/public": {
      "get": {"summary": "no auth"}
    },
    "/secure": {
      "get": {"summary": "auth required", "security": [{"bearerAuth": []}]}
    }
  }
}
"""

TERRAFORM_CONFIG = """\
resource "aws_security_group_rule" "open" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_s3_bucket_acl" "public" {
  acl = "public-read"
}
"""


def test_docker_compose_flags_exposed_port_privileged_and_secret() -> None:
    summary = extract_attack_surface(DOCKER_COMPOSE, "docker-compose")
    categories = {i.category for i in summary.issues}
    assert "exposed_port" in categories
    assert "privileged_container" in categories
    assert "hardcoded_secret" in categories
    # The env-var-referenced password on the db service must not be flagged.
    secret_issues = [i for i in summary.issues if i.category == "hardcoded_secret"]
    assert len(secret_issues) == 1
    assert "web" in secret_issues[0].location


def test_kubernetes_flags_privileged_root_and_host_network() -> None:
    summary = extract_attack_surface(KUBERNETES_MANIFEST, "kubernetes")
    categories = {i.category for i in summary.issues}
    assert "privileged_container" in categories
    assert "runs_as_root" in categories
    assert "host_network" in categories
    assert "no_resource_limits" in categories


def test_openapi_flags_missing_auth_only_on_unsecured_path() -> None:
    summary = extract_attack_surface(OPENAPI_DOC, "openapi")
    assert len(summary.issues) == 1
    assert summary.issues[0].category == "missing_auth"
    assert "/public" in summary.issues[0].location


def test_terraform_flags_open_security_group_and_public_bucket() -> None:
    summary = extract_attack_surface(TERRAFORM_CONFIG, "terraform")
    categories = {i.category for i in summary.issues}
    assert "open_security_group" in categories
    assert "public_s3_bucket" in categories


def test_unsupported_config_type_raises() -> None:
    with pytest.raises(AttackSurfaceParseError, match="unsupported config_type"):
        extract_attack_surface("{}", "cloudformation")


def test_invalid_yaml_raises_parse_error() -> None:
    with pytest.raises(AttackSurfaceParseError):
        extract_attack_surface("services:\n  web: [unclosed", "docker-compose")
