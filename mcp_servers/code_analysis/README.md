# nexus-mcp-code-analysis

Code / config analysis MCP server. Lets NEXUS reason about the actual
dependencies, source, and infra config of a target architecture instead of
only its free-text description.

## Tools

- `analyze_dependencies(requirements_content)` — parses `requirements.txt`
  or `pyproject.toml` and looks each package up on NVD by keyword. Returns
  JSON `list[DependencyFinding]` (package, version, CVEs).
- `detect_patterns(code_content, language="python")` — runs semgrep's
  `auto` ruleset against a code snippet. Returns JSON `list[PatternFinding]`
  (rule_id, message, line, severity).
- `extract_attack_surface(config_content, config_type)` — parses
  `docker-compose` / `kubernetes` / `openapi` / `terraform` config and
  flags exposed ports, privileged containers, missing auth, open security
  groups, public S3 buckets, hardcoded secrets. Returns JSON
  `AttackSurfaceSummary`.

## Setup

`detect_patterns` shells out to the `semgrep` binary — install it
separately (it is not a Python dependency of this package):

```bash
pip install semgrep  # or: brew install semgrep
```

If `semgrep` is not on `PATH`, `detect_patterns` returns an
`MCPToolError` with `error_type="semgrep_error"` rather than raising —
callers should treat that source as temporarily unavailable, same as any
other MCP tool failure.

`analyze_dependencies` calls the public NVD REST API directly (a small,
self-contained client — not a cross-package import of
`mcp_servers/nvd`). Set `NVD_API_KEY` to raise the rate limit from 5 to 50
req/s, same convention as the NVD server.

Terraform parsing is regex-based (no HCL parser dependency) and only
catches the two canonical misconfigurations: open security groups
(`cidr_blocks` containing `0.0.0.0/0`) and public S3 buckets (`public-read`
ACLs / disabled public-access-block settings).

## Run

```bash
python mcp_servers/code_analysis/server.py
```
