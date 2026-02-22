"""调试器转发工具。"""
from __future__ import annotations

from typing import Optional, Any, Annotated

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kwargs: None  # type: ignore

import sys
import os
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

from _state import forward  # type: ignore


def register_tools(server: Any) -> None:
    """注册调试器工具到服务器。"""
    
    @server.tool(description="Start debugger process.")
    def dbg_start(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """启动调试器。"""
        return forward("dbg_start", {}, port, timeout=timeout)
    
    @server.tool(description="Exit/terminate debugger process.")
    def dbg_exit(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """退出调试器。"""
        return forward("dbg_exit", {}, port, timeout=timeout)
    
    @server.tool(description="Continue debugger execution.")
    def dbg_continue(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """继续执行。"""
        return forward("dbg_continue", {}, port, timeout=timeout)
    
    @server.tool(description="Step into next instruction.")
    def dbg_step_into(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """单步进入。"""
        return forward("dbg_step_into", {}, port, timeout=timeout)
    
    @server.tool(description="Step over next instruction.")
    def dbg_step_over(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """单步跳过。"""
        return forward("dbg_step_over", {}, port, timeout=timeout)
    
    @server.tool(description="Run to address.")
    def dbg_run_to(
        addr: Annotated[str, Field(description="Target address")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """运行到指定地址。"""
        return forward("dbg_run_to", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Get all CPU registers.")
    def dbg_regs(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取寄存器。"""
        return forward("dbg_regs", {}, port, timeout=timeout)
    
    @server.tool(description="Get call stack.")
    def dbg_callstack(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取调用栈。"""
        return forward("dbg_callstack", {}, port, timeout=timeout)
    
    @server.tool(description="List all breakpoints.")
    def dbg_list_bps(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出断点。"""
        return forward("dbg_list_bps", {}, port, timeout=timeout)
    
    @server.tool(description="Add breakpoint at address.")
    def dbg_add_bp(
        addr: Annotated[str, Field(description="Breakpoint address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """设置断点。"""
        return forward("dbg_add_bp", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Delete breakpoint at address.")
    def dbg_delete_bp(
        addr: Annotated[str, Field(description="Breakpoint address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """删除断点。"""
        return forward("dbg_delete_bp", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Enable or disable breakpoint.")
    def dbg_enable_bp(
        items: Annotated[list, Field(description="List of {address, enable} objects")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """启用/禁用断点。"""
        return forward("dbg_enable_bp", {"items": items}, port, timeout=timeout)
    
    @server.tool(description="Read memory in debugger.")
    def dbg_read_mem(
        addr: Annotated[str, Field(description="Memory address")],
        size: Annotated[int, Field(description="Bytes to read")] = 64,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """调试器读取内存。"""
        return forward("dbg_read_mem", {"addr": addr, "size": size}, port, timeout=timeout)
    
    @server.tool(description="Write memory in debugger.")
    def dbg_write_mem(
        addr: Annotated[str, Field(description="Memory address")],
        data: Annotated[str, Field(description="Hex string to write")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """调试器写入内存。"""
        return forward("dbg_write_mem", {"addr": addr, "data": data}, port, timeout=timeout)
