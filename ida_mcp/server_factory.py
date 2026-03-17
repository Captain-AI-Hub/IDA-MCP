"""Composition root for IDA-side FastMCP servers."""
from __future__ import annotations

import os
from typing import Optional

from .rpc import get_resources, get_tool_specs

__version__ = "0.2.0"


def _ensure_api_modules_loaded() -> None:
    # Import side-effect modules only when assembling the runtime server.
    from . import api_analysis  # noqa: F401
    from . import api_core  # noqa: F401
    from . import api_debug  # noqa: F401
    from . import api_lifecycle  # noqa: F401
    from . import api_memory  # noqa: F401
    from . import api_modeling  # noqa: F401
    from . import api_modify  # noqa: F401
    from . import api_python  # noqa: F401
    from . import api_resources  # noqa: F401
    from . import api_stack  # noqa: F401
    from . import api_types  # noqa: F401


def create_mcp_server(
    name: Optional[str] = None,
    enable_unsafe: bool = True,
) -> "FastMCP":  # type: ignore[name-defined]
    """Create the FastMCP server used inside an IDA instance."""
    from fastmcp import FastMCP

    _ensure_api_modules_loaded()

    if name is None:
        name = os.getenv("IDA_MCP_NAME", "IDA-MCP")

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
