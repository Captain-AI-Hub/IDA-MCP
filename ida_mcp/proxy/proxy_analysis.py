"""分析转发工具 - 反编译、反汇编、交叉引用。"""
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
    """注册分析工具到服务器。"""
    
    @server.tool(description="Decompile function(s). addr can be address or name, comma-separated for batch.")
    def decompile(
        addr: Annotated[str, Field(description="Function address(es) or name(s), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """反编译函数。"""
        return forward("decompile", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Disassemble function(s). addr can be address or name, comma-separated for batch.")
    def disasm(
        addr: Annotated[str, Field(description="Function address(es) or name(s), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """反汇编函数。"""
        return forward("disasm", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Linear disassembly from address. Returns raw instructions.")
    def linear_disassemble(
        start_address: Annotated[str, Field(description="Start address")],
        count: Annotated[int, Field(description="Number of instructions")] = 20,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """线性反汇编。"""
        return forward("linear_disassemble", {"start_address": start_address, "count": count}, port, timeout=timeout)
    
    @server.tool(description="Get cross-references TO address(es). addr comma-separated for batch.")
    def xrefs_to(
        addr: Annotated[str, Field(description="Target address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取到地址的交叉引用。"""
        return forward("xrefs_to", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Get cross-references FROM address(es).")
    def xrefs_from(
        addr: Annotated[str, Field(description="Source address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取从地址的交叉引用。"""
        return forward("xrefs_from", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Get cross-references to struct field. struct_name: type name, field_name: member name.")
    def xrefs_to_field(
        struct_name: Annotated[str, Field(description="Structure type name")],
        field_name: Annotated[str, Field(description="Field/member name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取结构体字段的交叉引用。"""
        return forward("xrefs_to_field", {
            "struct_name": struct_name,
            "field_name": field_name
        }, port, timeout=timeout)
    
    @server.tool(description="Find function by name or address.")
    def get_function(
        query: Annotated[str, Field(description="Function name or address")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """查找函数。"""
        return forward("get_function", {"query": query}, port, timeout=timeout)
    
    @server.tool(description="Search for byte pattern with wildcards (e.g. '48 8B ?? ?? 48 89').")
    def find_bytes(
        pattern: Annotated[str, Field(description="Byte pattern with wildcards")],
        start: Annotated[Optional[str], Field(description="Start address")] = None,
        end: Annotated[Optional[str], Field(description="End address")] = None,
        limit: Annotated[int, Field(description="Max results")] = 100,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """字节模式搜索。"""
        params: dict[str, Any] = {"pattern": pattern, "limit": limit}
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        return forward("find_bytes", params, port, timeout=timeout)
    
    @server.tool(description="Get basic blocks with control flow information.")
    def get_basic_blocks(
        addr: Annotated[str, Field(description="Function address or name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取基本块。"""
        return forward("get_basic_blocks", {"addr": addr}, port, timeout=timeout)
