"""Gateway FastMCP proxy server instance.

This module creates the FastMCP server used by the gateway MCP proxy and
registers all forwarded tools.
"""
from __future__ import annotations

from typing import Optional, Annotated, Any

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kwargs: None  # type: ignore

from fastmcp import FastMCP

from ..errors import error_payload
from ..rpc import text_result_tool
from ._http import http_get
from ._state import (
    choose_port,
    get_instances,
    is_valid_port,
    set_selected_port,
)
from . import register_tools


# ============================================================================
# FastMCP server (single instance)
# ============================================================================

server = FastMCP(
    name="IDA-MCP-Proxy",
    version="0.8.0",
    instructions="""IDA MCP 代理 - 通过网关访问多个 IDA 实例。

多实例时用 list_instances 查看实例，用 select_instance 或工具参数 port 指定目标；
open_in_ida / close_ida / shutdown_gateway 管理生命周期。
其余工具覆盖反汇编、反编译、xref、搜索、修改、内存、类型、栈帧与调试。"""
)


# ============================================================================
# Core management tools
# ============================================================================

def check_connection() -> dict:
    """Check gateway connection status."""
    data = http_get('/instances')
    if not isinstance(data, list):
        return {"ok": False, "count": 0}
    return {"ok": True, "count": len(data)}


server.tool(description="Health check. Returns {ok: bool, count: int} where count is number of registered IDA instances.")(text_result_tool(check_connection))


def list_instances() -> list:
    """List all registered IDA instances."""
    return get_instances()


server.tool(description="List all registered IDA instances. Returns array of {id, port, pid, input_file, started, ...}.")(text_result_tool(list_instances))


def select_instance(
    port: Annotated[Optional[int], Field(description="Target port; omit for auto-select")] = None
) -> dict:
    """Select the default target instance for subsequent proxied calls."""
    selected_port = choose_port(port)
    if selected_port is not None:
        set_selected_port(selected_port)
        return {"selected_port": selected_port}

    instances = get_instances()
    if not instances:
        return error_payload("no_instances", "No IDA instances available.")
    if port is not None and not any(i.get('port') == port for i in instances):
        return error_payload("instance_not_found", f"Port {port} not found in registered instances.", port=port)

    return error_payload("selection_failed", "Failed to select instance.")


server.tool(description="Choose the default IDA instance port for subsequent calls. If port omitted, auto-selects (prefer 10000). Returns {selected_port} or {error}.")(text_result_tool(select_instance))


# ============================================================================
# Register categorized tools
# ============================================================================

register_tools.register_tools(server)

