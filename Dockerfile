FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Bundled MCP servers run as stdio subprocesses of the app process (see
# nexus.mcp.client._default_server_configs) — they need their own source
# tree on disk. Not pip-installed: their sibling packages share flat
# module names (server.py, client.py, schemas.py), which would collide in
# a shared site-packages. Their extra runtime deps (numpy for atlas) are
# folded into this image's own dependencies above instead.
COPY mcp_servers/ ./mcp_servers/

EXPOSE 8000
CMD ["uvicorn", "src.nexus.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
