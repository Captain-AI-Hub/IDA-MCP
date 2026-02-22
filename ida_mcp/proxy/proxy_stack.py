"""栈帧转发工具 - 栈帧信息、变量声明/删除。"""
from __future__ import annotations

from typing import Optional, Any, Annotated, List, Dict

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
    """注册栈帧工具到服务器。"""
    
    @server.tool(description="Get stack frame variables for function(s). addr can be address or name, comma-separated for batch.")
    def stack_frame(
        addr: Annotated[str, Field(description="Function address(es) or name(s), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取栈帧变量。"""
        return forward("stack_frame", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Declare stack variable(s). items: [{function_address, offset, name, type?, size?}].")
    def declare_stack(
        items: Annotated[List[Dict[str, Any]], Field(description="List of stack variable definitions")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """声明栈变量。"""
        return forward("declare_stack", {"items": items}, port, timeout=timeout)
    
    @server.tool(description="Delete stack variable(s). items: [{function_address, name}].")
    def delete_stack(
        items: Annotated[List[Dict[str, Any]], Field(description="List of {function_address, name}")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """删除栈变量。"""
        return forward("delete_stack", {"items": items}, port, timeout=timeout)

