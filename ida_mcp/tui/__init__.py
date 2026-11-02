"""Host-side terminal UI for IDA-MCP (v1.1).

- ``ida_mcp.tui.dump``: non-interactive asm/pseudocode export.
- ``ida_mcp.tui.app``: interactive textual TUI (optional dependency).

These run in the MCP-server environment (uvx side) and talk to workers
through the normal bridge; nothing here is loaded inside a worker.
"""
