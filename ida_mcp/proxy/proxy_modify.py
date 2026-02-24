"""修改转发工具 - 注释、重命名。"""
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
    """注册修改工具到服务器。"""
    
    @server.tool(description="Set comment at address(es). items: [{address, comment}].")
    def set_comment(
        items: Annotated[list, Field(description="List of {address, comment} objects")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """设置注释。"""
        return forward("set_comment", {"items": items}, port, timeout=timeout)
    
    @server.tool(description="Rename a function.")
    def rename_function(
        address: Annotated[str, Field(description="Function address or name")],
        new_name: Annotated[str, Field(description="New function name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """重命名函数。"""
        return forward("rename_function", {
            "function_address": address,
            "new_name": new_name
        }, port, timeout=timeout)
    
    @server.tool(description="Rename a global variable.")
    def rename_global_variable(
        old_name: Annotated[str, Field(description="Current variable name")],
        new_name: Annotated[str, Field(description="New variable name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """重命名全局变量。"""
        return forward("rename_global_variable", {
            "old_name": old_name,
            "new_name": new_name
        }, port, timeout=timeout)
    
    @server.tool(description="Rename a local variable in a function.")
    def rename_local_variable(
        function_address: Annotated[str, Field(description="Function containing the variable")],
        old_name: Annotated[str, Field(description="Current variable name")],
        new_name: Annotated[str, Field(description="New variable name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """重命名局部变量。"""
        return forward("rename_local_variable", {
            "function_address": function_address,
            "old_name": old_name,
            "new_name": new_name
        }, port, timeout=timeout)
    
    @server.tool(description="Patch bytes at address(es). items: [{address, bytes: [int,...] or hex_string}].")
    def patch_bytes(
        items: Annotated[list, Field(description="List of {address, bytes} objects")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """字节补丁。"""
        return forward("patch_bytes", {"items": items}, port, timeout=timeout)