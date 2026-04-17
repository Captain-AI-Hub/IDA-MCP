"""Public package surface for IDA-MCP."""
from __future__ import annotations

try:
    from .config import get_ida_default_port

    DEFAULT_PORT = get_ida_default_port()
except Exception:
    DEFAULT_PORT = 10000

from .rpc import tool, resource, unsafe, get_tools, get_resources, is_unsafe
from .server_factory import create_mcp_server
from .sync import idaread, idawrite
from .utils import (
    parse_address,
    normalize_list_input,
    paginate,
    pattern_filter,
    is_valid_c_identifier,
)

__all__ = [
    "DEFAULT_PORT",
    "create_mcp_server",
    "tool",
    "resource",
    "unsafe",
    "get_tools",
    "get_resources",
    "is_unsafe",
    "idaread",
    "idawrite",
    "parse_address",
    "normalize_list_input",
    "paginate",
    "pattern_filter",
    "is_valid_c_identifier",
]
