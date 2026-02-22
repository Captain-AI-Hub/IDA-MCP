"""类型转发工具 - 类型声明、应用。"""
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
    """注册类型工具到服务器。"""
    
    @server.tool(description="Set function prototype/signature.")
    def set_function_prototype(
        function_address: Annotated[str, Field(description="Function address")],
        prototype: Annotated[str, Field(description="C-style function prototype")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """设置函数原型。"""
        return forward("set_function_prototype", {
            "function_address": function_address,
            "prototype": prototype
        }, port, timeout=timeout)
    
    @server.tool(description="Set type of a local variable.")
    def set_local_variable_type(
        function_address: Annotated[str, Field(description="Function containing the variable")],
        variable_name: Annotated[str, Field(description="Variable name")],
        new_type: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """设置局部变量类型。"""
        return forward("set_local_variable_type", {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type
        }, port, timeout=timeout)
    
    @server.tool(description="Set type of a global variable.")
    def set_global_variable_type(
        variable_name: Annotated[str, Field(description="Global variable name")],
        new_type: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """设置全局变量类型。"""
        return forward("set_global_variable_type", {
            "variable_name": variable_name,
            "new_type": new_type
        }, port, timeout=timeout)
    
    @server.tool(description="Declare a new C type (struct, enum, typedef).")
    def declare_type(
        decl: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """声明新类型。"""
        return forward("declare_type", {"decl": decl}, port, timeout=timeout)
    
    @server.tool(description="List all structures/unions defined in the database.")
    def list_structs(
        pattern: Annotated[Optional[str], Field(description="Optional name filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出结构体。"""
        params: dict[str, Any] = {}
        if pattern:
            params["pattern"] = pattern
        return forward("list_structs", params, port, timeout=timeout)
    
    @server.tool(description="Get detailed structure/union definition with fields.")
    def get_struct_info(
        name: Annotated[str, Field(description="Structure/union name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取结构体详情。"""
        return forward("get_struct_info", {"name": name}, port, timeout=timeout)
