"""IDA call execution helpers.

Provides:
    @idaread   - marker for read-only SDK access (kept for catalog parity)
    @idawrite  - marker for read/write SDK access

idalib workers execute every SDK call on the process main thread; the bridge
serializes calls through its main-thread queue, so the decorators run the
function inline. The historical GUI marshalling via
``ida_kernwin.execute_sync`` is gone together with GUI support.
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, TypeVar

try:
    import ida_auto  # type: ignore
except ImportError:
    ida_auto = None

F = TypeVar('F', bound=Callable[..., Any])


def idaread(fn: F) -> F:
    """Wrap function for read-only SDK execution (runs inline in workers)."""
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)
    # Preserve the original function's signature for Pydantic/FastMCP
    wrapper.__signature__ = inspect.signature(fn)  # type: ignore
    wrapper._ida_exec_mode = "read"  # type: ignore[attr-defined]
    return wrapper  # type: ignore


def idawrite(fn: F) -> F:
    """Wrap function for read/write SDK execution (runs inline in workers)."""
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)
    wrapper.__signature__ = inspect.signature(fn)  # type: ignore
    wrapper._ida_exec_mode = "write"  # type: ignore[attr-defined]
    return wrapper  # type: ignore


def run_in_main_thread(fn: Callable[[], Any], write: bool = False) -> Any:
    """Execute a function on the worker's main thread (inline; kept for API
    parity with the deleted GUI marshalling)."""
    return fn()


def wait_for_auto_analysis() -> None:
    """Wait for IDA auto-analysis to complete."""
    if ida_auto is None:
        return
    try:
        ida_auto.auto_wait()
    except Exception:
        pass
