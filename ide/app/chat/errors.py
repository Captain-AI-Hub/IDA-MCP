"""Chat-specific exceptions and error types."""

from __future__ import annotations


class ChatError(Exception):
    """Base exception for chat feature."""


class ProviderNotConfiguredError(ChatError):
    """No model provider is configured or the selected one is invalid."""


class McpConnectionError(ChatError):
    """Failed to connect to an MCP server."""

    def __init__(self, server_name: str, detail: str = "") -> None:
        self.server_name = server_name
        msg = f"MCP connection failed: {server_name}"
        if detail:
            msg += f" — {detail}"
        super().__init__(msg)


class AgentBuildError(ChatError):
    """Failed to construct the LangGraph agent."""


class AgentRunError(ChatError):
    """Agent execution failed."""

    def __init__(self, detail: str = "", *, recoverable: bool = True) -> None:
        self.recoverable = recoverable
        super().__init__(detail)


class ToolExecutionError(ChatError):
    """A tool call returned an error."""

    def __init__(
        self, tool_name: str, server_name: str, detail: str = ""
    ) -> None:
        self.tool_name = tool_name
        self.server_name = server_name
        msg = f"Tool {tool_name!r} on {server_name!r} failed"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class PersistenceError(ChatError):
    """Database operation for chat data failed."""
