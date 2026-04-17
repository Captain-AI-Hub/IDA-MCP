"""IDA lifecycle API - runtime control inside an IDA process."""
from __future__ import annotations

from typing import Annotated

from .rpc import tool
from .sync import idawrite

try:
    import ida_loader  # type: ignore
    import ida_pro  # type: ignore
except ImportError:
    ida_loader = None
    ida_pro = None


@tool
@idawrite
def close_ida(
    save: Annotated[bool, "Whether to save IDB file before closing"] = True,
) -> dict:
    """Close IDA Pro instance. Warning: This terminates the process."""
    try:
        if save:
            if ida_loader is None or not ida_loader.save_database(None, 0):
                return {"error": "Failed to save database"}

        if ida_pro is None:
            return {"error": "IDA runtime unavailable"}

        ida_pro.qexit(0)
        return {"status": "ok", "message": "IDA is closing"}
    except Exception as e:
        return {"error": str(e)}
