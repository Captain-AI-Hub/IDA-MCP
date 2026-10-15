"""Public package surface for IDA-MCP."""

from __future__ import annotations

__version__ = "0.9.0"

from .rpc import tool, get_tools
from .sync import idaread, idawrite
from .utils import (
    parse_address,
    normalize_list_input,
    paginate,
    pattern_filter,
    is_valid_c_identifier,
)

__all__ = [
    "__version__",
    "tool",
    "get_tools",
    "idaread",
    "idawrite",
    "parse_address",
    "normalize_list_input",
    "paginate",
    "pattern_filter",
    "is_valid_c_identifier",
]
