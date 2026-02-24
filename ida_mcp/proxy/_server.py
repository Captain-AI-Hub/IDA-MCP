"""共享的 FastMCP Server 实例。

此模块创建一个 FastMCP server 并注册所有工具。
ida_mcp_proxy.py 和 http_server.py 都应该导入此模块的 server。

这确保 stdio 和 HTTP 两种传输方式使用完全相同的 server 实例。
"""
from __future__ import annotations

import sys
import os
from typing import Optional, Annotated, Any

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kwargs: None  # type: ignore

from fastmcp import FastMCP

# 确保当前目录在路径中
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

# 导入辅助模块
from _http import http_get, http_post  # type: ignore
from _state import (  # type: ignore
    get_instances,
    is_valid_port,
    get_current_port,
    set_current_port,
)

# 导入工具注册函数
import proxy_core  # type: ignore
import proxy_analysis  # type: ignore
import proxy_modify  # type: ignore
import proxy_memory  # type: ignore
import proxy_types  # type: ignore
import proxy_debug  # type: ignore
import proxy_python  # type: ignore
import proxy_stack  # type: ignore


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

多实例时请先用 list_instances 查看可用实例，再用 select_instance 选择目标。
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


@server.tool(description="Select default IDA instance by port. If port omitted, auto-selects (prefer 10000). Returns {selected_port} or {error}.")
def select_instance(
    port: Annotated[Optional[int], Field(description="Target port; omit for auto-select")] = None
) -> dict:
    """选择默认目标实例。"""
    payload = {"port": port} if port is not None else {}
    res = http_post('/select_instance', payload)
    
    if isinstance(res, dict) and is_valid_port(res.get('selected_port')):
        set_current_port(int(res['selected_port']))
        return {"selected_port": get_current_port()}
    
    # 错误处理
    instances = get_instances()
    if not instances:
        return {"error": "No IDA instances available"}
    if port is not None and not any(i.get('port') == port for i in instances):
        return {"error": f"Port {port} not found in registered instances"}
    
    return {"error": "Failed to select instance"}


# ============================================================================
# 注册分类工具
# ============================================================================

proxy_core.register_tools(server)
proxy_analysis.register_tools(server)
proxy_modify.register_tools(server)
proxy_memory.register_tools(server)
proxy_types.register_tools(server)
proxy_debug.register_tools(server)
proxy_python.register_tools(server)
proxy_stack.register_tools(server)

