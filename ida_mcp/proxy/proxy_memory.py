"""内存转发工具 - 内存读取。"""
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
    """注册内存工具到服务器。"""
    
    @server.tool(description="Read memory bytes. Returns hex dump and byte array.")
    def get_bytes(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        size: Annotated[int, Field(description="Bytes to read (1-4096)")] = 64,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """读取内存字节。"""
        return forward("get_bytes", {"addr": addr, "size": size}, port, timeout=timeout)
    
    @server.tool(description="Read 8-bit unsigned integer from address.")
    def get_u8(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """读取 8 位无符号整数。"""
        return forward("get_u8", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Read 16-bit unsigned integer from address.")
    def get_u16(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """读取 16 位无符号整数。"""
        return forward("get_u16", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Read 32-bit unsigned integer from address.")
    def get_u32(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """读取 32 位无符号整数。"""
        return forward("get_u32", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Read 64-bit unsigned integer from address.")
    def get_u64(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """读取 64 位无符号整数。"""
        return forward("get_u64", {"addr": addr}, port, timeout=timeout)
    
    @server.tool(description="Read null-terminated string from address.")
    def get_string(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        max_len: Annotated[int, Field(description="Maximum length")] = 256,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """读取字符串。"""
        return forward("get_string", {"addr": addr, "max_len": max_len}, port, timeout=timeout)
