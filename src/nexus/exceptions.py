"""Typed exceptions for the NEXUS pipeline."""


class NexusBaseError(Exception):
    """Base class for all NEXUS exceptions."""


class AgentError(NexusBaseError):
    """Raised by agent nodes when processing fails."""


class MemoryLayerError(NexusBaseError):
    """Raised by the memory layer (Redis / pgvector)."""


class MCPClientError(NexusBaseError):
    """Raised by the MCP client when a server call fails."""


class PipelineTimeoutError(NexusBaseError):
    """Raised when the pipeline exceeds the configured time limit."""
