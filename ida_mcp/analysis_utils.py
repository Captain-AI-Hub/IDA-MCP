"""Shared analysis utilities for decompilation helpers."""
from __future__ import annotations

from typing import Any

# IDA module imports
try:
    import ida_auto  # type: ignore
    import ida_hexrays  # type: ignore
except ImportError:
    ida_auto = None
    ida_hexrays = None


def decompile_silent(ea: int) -> Any:
    """Decompile with dialog suppression (segment read-only warnings, etc.)."""
    try:
        old = ida_auto.set_query_graph(0) if ida_auto else 0
        cfunc = ida_hexrays.decompile(ea)  # type: ignore[union-attr]
        if ida_auto:
            ida_auto.set_query_graph(old)
        return cfunc
    except Exception:
        return None
