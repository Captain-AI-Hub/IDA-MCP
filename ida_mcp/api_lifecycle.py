"""IDA lifecycle API - runtime control inside an IDA process.

Provides tools:
    - close_ida   close the IDA instance
    - save_idb    save the current database
"""
from __future__ import annotations

import threading
from typing import Annotated

from .rpc import tool
from .sync import idawrite

try:
    import ida_kernwin  # type: ignore
    import ida_loader  # type: ignore
    import ida_pro  # type: ignore
except ImportError:
    ida_kernwin = None
    ida_loader = None
    ida_pro = None


def _request_qexit_later() -> None:
    """Request IDA shutdown after the MCP response has had a chance to flush."""
    if ida_pro is None:
        return

    def _qexit() -> int:
        ida_pro.qexit(0)
        return 0

    def _run() -> None:
        try:
            if ida_kernwin is not None:
                ida_kernwin.execute_sync(_qexit, ida_kernwin.MFF_WRITE)
            else:
                ida_pro.qexit(0)
        except Exception:
            pass

    timer = threading.Timer(0.25, _run)
    timer.daemon = True
    timer.start()


@tool
@idawrite
def close_ida(
    save: Annotated[bool, "Whether to save IDB file before closing"] = True,
) -> dict:
    """Close IDA Pro instance. Warning: This terminates the process."""
    try:
        if save:
            if ida_loader is None:
                return {"error": "IDA runtime unavailable (ida_loader)"}
            # ida_loader.save_database() returns None (void) on success.
            ida_loader.save_database(None, 0)

        if ida_pro is None:
            return {"error": "IDA runtime unavailable"}

        _request_qexit_later()
        return {
            "status": "ok",
            "message": "IDA close requested",
            "save": bool(save),
        }
    except Exception as e:
        return {"error": str(e)}


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
