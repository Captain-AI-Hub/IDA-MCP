"""MCP client pool — persistent MultiServerMCPClient lifecycle management."""

from __future__ import annotations

import logging
from typing import Any

from app.chat.errors import McpConnectionError

logger = logging.getLogger(__name__)


class McpClientPool:
    """Manages persistent MCP client connections.

    Lazy-connects on first tool request, keeps clients alive for reuse,
    and provides health-check / reconnect on failure.
    """

    def __init__(self) -> None:
        self._client: Any | None = None  # MultiServerMCPClient
        self._server_configs: dict[str, dict[str, Any]] = {}
        self._tools: list[Any] = []  # list[BaseTool]
        self._connected: bool = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def tools(self) -> list[Any]:
        return list(self._tools)

    async def connect(
        self, server_configs: dict[str, dict[str, Any]]
    ) -> list[Any]:
        """Connect (or reconnect) to MCP servers and return available tools.

        Args:
            server_configs: Dict mapping server name → connection config,
                            as produced by McpServerEntry.to_langchain_config().
        """
        if self._connected and self._server_configs == server_configs:
            return self._tools

        # Disconnect previous client if any
        await self.disconnect()

        self._server_configs = dict(server_configs)

        if not server_configs:
            self._tools = []
            self._connected = True
            return self._tools

        try:
            from langchain_mcp_adapters.client import MultiServerMCPClient

            self._client = MultiServerMCPClient(
                server_configs, tool_name_prefix=True
            )
            self._tools = await self._client.get_tools()
            self._connected = True
            logger.info(
                "MCP pool connected: %d tools from %d servers",
                len(self._tools),
                len(server_configs),
            )
            return self._tools
        except Exception as exc:
            self._client = None
            self._connected = False
            logger.error("MCP pool connection failed: %s", exc)
            raise McpConnectionError(
                ", ".join(server_configs.keys()), str(exc)
            ) from exc

    async def reconnect(self) -> list[Any]:
        """Reconnect using the last known server configs."""
        if not self._server_configs:
            return []
        return await self.connect(self._server_configs)

    async def disconnect(self) -> None:
        """Cleanly close all MCP connections."""
        if self._client is not None:
            try:
                # MultiServerMCPClient may have a close/cleanup method
                if hasattr(self._client, "close"):
                    await self._client.close()
                elif hasattr(self._client, "__aexit__"):
                    await self._client.__aexit__(None, None, None)
            except Exception as exc:
                logger.warning("Error closing MCP client: %s", exc)
            finally:
                self._client = None
        self._tools = []
        self._connected = False

    def filter_tools(
        self,
        tools: list[Any],
        allowlist: set[str] | None = None,
        denylist: set[str] | None = None,
    ) -> list[Any]:
        """Apply allow/deny lists to a set of tools."""
        result = tools
        if allowlist is not None:
            result = [t for t in result if t.name in allowlist]
        if denylist is not None:
            result = [t for t in result if t.name not in denylist]
        return result
