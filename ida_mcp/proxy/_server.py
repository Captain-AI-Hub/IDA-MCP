"""共享的 FastMCP Server 实例。

此模块创建一个 FastMCP server 并注册所有工具。
ida_mcp_proxy.py 和 http_server.py 都应该导入此模块的 server。

这确保 stdio 和 HTTP 两种传输方式使用完全相同的 server 实例。
"""
from __future__ import annotations

from typing import Optional, Annotated, Any

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kwargs: None  # type: ignore

from fastmcp import FastMCP

from ._http import http_get
from ._state import (
    choose_port,
    get_instances,
    is_valid_port,
)
from . import register_tools


# ============================================================================
# FastMCP 服务器（唯一实例）
# ============================================================================

server = FastMCP(
    name="IDA-MCP-Proxy",
    instructions="""IDA MCP 代理 - 通过协调器访问多个 IDA 实例。

核心管理:
- check_connection: 检查连接状态
- list_instances: 列出所有 IDA 实例
- select_instance: 选择要操作的实例

生命周期工具:
- open_in_ida: 启动 IDA 并打开指定文件
- close_ida: 关闭目标 IDA 实例

核心工具:
- list_functions, get_metadata, list_strings, list_globals, list_local_types, get_entry_points

分析工具:
- decompile, disasm, linear_disassemble, xrefs_to, xrefs_from, get_function

修改工具:
- set_comment, rename_function, rename_global_variable, rename_local_variable

内存工具:
- get_bytes, get_u8, get_u16, get_u32, get_u64, get_string

类型工具:
- set_function_prototype, set_local_variable_type, set_global_variable_type, declare_type

调试工具:
- dbg_start, dbg_exit, dbg_continue, dbg_step_into, dbg_step_over
- dbg_regs, dbg_callstack, dbg_add_bp, dbg_delete_bp, dbg_list_bps

栈帧工具:
- stack_frame, declare_stack, delete_stack

多实例时请先用 list_instances 查看可用实例，并优先在工具参数里显式传递 port。
"""
)


# ============================================================================
# 核心管理工具
# ============================================================================

@server.tool(description="Health check. Returns {ok: bool, count: int} where count is number of registered IDA instances.")
def check_connection() -> dict:
    """检查协调器连接状态。"""
    data = http_get('/instances')
    if not isinstance(data, list):
        return {"ok": False, "count": 0}
    return {"ok": True, "count": len(data)}


@server.tool(description="List all registered IDA instances. Returns array of {id, port, pid, input_file, started, ...}.")
def list_instances() -> list:
    """列出所有已注册的 IDA 实例。"""
    return get_instances()


@server.tool(description="Choose a recommended IDA instance port. If port omitted, auto-selects (prefer 10000). Returns {selected_port} or {error}.")
def select_instance(
    port: Annotated[Optional[int], Field(description="Target port; omit for auto-select")] = None
) -> dict:
    """选择推荐目标实例，不写入跨客户端共享状态。"""
    selected_port = choose_port(port)
    if selected_port is not None:
        return {"selected_port": selected_port}

    instances = get_instances()
    if not instances:
        return {"error": "No IDA instances available"}
    if port is not None and not any(i.get('port') == port for i in instances):
        return {"error": f"Port {port} not found in registered instances"}

    return {"error": "Failed to select instance"}


# ============================================================================
# 注册分类工具
# ============================================================================

register_tools.register_tools(server)

