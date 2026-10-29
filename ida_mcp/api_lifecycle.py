"""IDA lifecycle API - runtime control inside an idalib worker.

Provides tools:
    - save_idb          save the current database
    - wait_for_analysis block until IDA auto-analysis finishes

Process shutdown is handled by the worker's /shutdown path (graceful save
and exit), driven by close_database on the MCP server side.
"""
from __future__ import annotations

from typing import Annotated

from .rpc import tool
from .sync import idaread, idawrite, wait_for_auto_analysis

try:
    import ida_loader  # type: ignore
except ImportError:
    ida_loader = None


@tool
@idawrite
def save_idb(
    path: Annotated[str, "Target .i64/.idb path; empty keeps the current database path"] = "",
) -> dict:
    """Save the current IDA database to disk."""
    if ida_loader is None:
        return {"error": "IDA runtime unavailable (ida_loader)"}
    target = str(path).strip() or None
    try:
        # ida_loader.save_database() returns None (void) on success.
        ida_loader.save_database(target, 0)
    except Exception as e:
        return {"error": f"save failed: {e}", "path": target}
    return {"saved": True, "path": target}


@tool
@idaread
def wait_for_analysis() -> dict:
    """Block until IDA auto-analysis (functions, xrefs, strings) completes."""
    try:
        wait_for_auto_analysis()
        return {"analyzed": True}
    except Exception as e:
        return {"error": str(e)}
