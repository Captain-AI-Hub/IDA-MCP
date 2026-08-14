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
    version="0.7.1",
    instructions="""IDA MCP 代理 - 通过网关访问多个 IDA 实例。

核心管理:
- check_connection: 检查连接状态
- list_instances: 列出所有 IDA 实例
- select_instance: 选择后续未显式指定 port 的默认 IDA 实例端口

生命周期工具:
- open_in_ida: 启动 IDA 并打开指定文件
- close_ida: 关闭目标 IDA 实例
- shutdown_gateway: 安全关闭独立网关进程

核心工具:
- list_functions, get_metadata, survey_binary, list_strings, list_globals, list_local_types, get_entry_points, convert_number

分析工具:
- decompile, disasm, linear_disasm, xrefs_to, xrefs_from, callgraph, trace_data_flow
- find_bytes, find_regex, search_text, find_instructions

修改工具:
- set_comment, rename_function, rename_global_variable, rename_local_variable
- patch_bytes, patch_asm, set_op_type, add_bookmark, force_recompile, diff_before_after

内存工具:
- get_bytes, read_scalar, get_string

类型工具:
- set_function_prototype, set_local_variable_type, set_global_variable_type, declare_struct, declare_enum, declare_typedef, infer_types

调试工具:
- dbg_start, dbg_exit, dbg_continue, dbg_step_into, dbg_step_over, dbg_status
- dbg_regs, dbg_thread_regs, dbg_callstack, dbg_add_bp, dbg_delete_bp, dbg_list_bps

栈帧工具:
- stack_frame, declare_stack, delete_stack

多实例时请先用 list_instances 查看可用实例，并优先在工具参数里显式传递 port。
"""
)


# ============================================================================
# Core management tools
# ============================================================================

@server.tool(description="Health check. Returns {ok: bool, count: int} where count is number of registered IDA instances.")
def check_connection() -> dict:
    """Check gateway connection status."""
    data = http_get('/instances')
    if not isinstance(data, list):
        return {"ok": False, "count": 0}
    return {"ok": True, "count": len(data)}


@server.tool(description="List all registered IDA instances. Returns array of {id, port, pid, input_file, started, ...}.")
def list_instances() -> list:
    """List all registered IDA instances."""
    return get_instances()


@server.tool(description="Choose the default IDA instance port for subsequent calls. If port omitted, auto-selects (prefer 10000). Returns {selected_port} or {error}.")
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


# ============================================================================
# Register categorized tools
# ============================================================================

register_tools.register_tools(server)

