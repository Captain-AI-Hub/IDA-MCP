"""Composition root for IDA-side FastMCP servers."""

from __future__ import annotations

from typing import Optional

from .config import get_server_name
from .rpc import get_resources, get_tool_specs, ensure_api_modules_loaded

__version__ = "0.2.0"


def create_mcp_server(
    name: Optional[str] = None,
    enable_unsafe: bool = True,
) -> "FastMCP":  # type: ignore[name-defined]
    """Create the FastMCP server used inside an IDA instance."""
    from fastmcp import FastMCP

    ensure_api_modules_loaded()

    if name is None:
        name = get_server_name()

    mcp = FastMCP(
        name=name,
        instructions="通过 MCP 工具访问 IDA 反汇编/分析数据。支持批量操作和 ida:// URI 资源访问。",
    )

    for spec in get_tool_specs().values():
        if spec.unsafe and not enable_unsafe:
            continue

        mcp.tool(description=spec.description)(spec.fn)

    for uri, fn in get_resources().items():
        try:
            mcp.resource(uri)(fn)
        except Exception as exc:
            print(f"[IDA-MCP] Failed to register resource {uri}: {exc}")

    return mcp
