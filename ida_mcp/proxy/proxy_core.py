"""核心转发工具 - 函数列表、元数据、字符串等。"""
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
    """注册核心工具到服务器。"""
    
    @server.tool(description="List functions with pagination. Params: offset (>=0), count (1-1000), pattern (optional filter).")
    def list_functions(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional name filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出函数。"""
        params: dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_functions", params, port, timeout=timeout)
    
    @server.tool(description="Get IDB metadata (input_file, arch, bits, hash, endian).")
    def get_metadata(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取 IDB 元数据。"""
        return forward("get_metadata", {}, port, timeout=timeout)
    
    @server.tool(description="List strings. Params: offset, count, pattern (optional filter).")
    def list_strings(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional content filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出字符串。"""
        params: dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_strings", params, port, timeout=timeout)
    
    @server.tool(description="List global variables. Params: offset, count, pattern (optional filter).")
    def list_globals(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional name filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出全局变量。"""
        params: dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_globals", params, port, timeout=timeout)
    
    @server.tool(description="List local types defined in IDB.")
    def list_local_types(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出本地类型。"""
        return forward("list_local_types", {}, port, timeout=timeout)
    
    @server.tool(description="Get entry points of the binary.")
    def get_entry_points(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取入口点。"""
        return forward("get_entry_points", {}, port, timeout=timeout)
    
    @server.tool(description="List imported functions with module names.")
    def list_imports(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional name/module filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出导入函数。"""
        params: dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_imports", params, port, timeout=timeout)
    
    @server.tool(description="List exported functions/symbols.")
    def list_exports(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional name filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出导出函数。"""
        params: dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_exports", params, port, timeout=timeout)
    
    @server.tool(description="List memory segments with permissions.")
    def list_segments(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """列出内存段。"""
        return forward("list_segments", {}, port, timeout=timeout)
    
    @server.tool(description="Get current cursor position and context in IDA.")
    def get_cursor(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """获取当前光标位置。"""
        return forward("get_cursor", {}, port, timeout=timeout)
