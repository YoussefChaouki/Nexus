"""Application settings loaded from environment variables."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralised configuration — never use os.environ directly."""

    # LLM providers
    openai_api_key: SecretStr
    anthropic_api_key: SecretStr | None = None

    # Observability — credentials optional: when missing the
    # observability layer falls back to a NullCallbackHandler.
    langfuse_public_key: SecretStr | None = None
    langfuse_secret_key: SecretStr | None = None
    langfuse_host: str = "https://cloud.langfuse.com"

    # Infrastructure
    redis_url: str = "redis://localhost:6379"
    postgres_dsn: str = "postgresql+asyncpg://nexus:nexus@localhost:5432/nexus"

    # External APIs
    nvd_api_key: SecretStr | None = None

    # Model configuration
    llm_model: str = "gpt-4o"
    # Agents emit structured JSON parsed by Pydantic — deterministic
    # decoding cuts validation retries; raise only for exploratory use.
    llm_temperature: float = 0.0
    # OpenAI SDK retries (exponential backoff, honours Retry-After) — a
    # transient 429 must never kill a multi-minute pipeline run.
    llm_max_retries: int = 5
    # Concurrent per-finding LLM/embedding calls. Keep modest: orgs on
    # low TPM tiers (30k tokens/min) hit 429 storms with aggressive bursts.
    llm_concurrency: int = 4
    embedding_model: str = "text-embedding-3-small"
    max_iterations: int = 3

    # Researcher relevance filtering (S8.T2)
    researcher_min_relevance: float = 0.5
    researcher_min_context_relevance: float = 0.35

    # Directory containing the bundled MCP server scripts (arxiv/nvd/atlas/
    # code_analysis), each launched as a stdio subprocess. None falls back
    # to a path guess relative to this package — only valid for an editable
    # / dev-mode install (e.g. `make dev`). A non-editable `pip install .`
    # (the Docker image) copies this package into site-packages, breaking
    # that guess — set explicitly there.
    mcp_servers_dir: str | None = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return cached Settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
