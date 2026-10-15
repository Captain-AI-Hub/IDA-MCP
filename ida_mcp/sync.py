"""IDA thread synchronization decorators.

Provides:
    @idaread   - wrap function for read-only execution in the IDA main thread
    @idawrite  - wrap function for read/write execution in the IDA main thread

Notes:
    In the IDA GUI all IDA SDK calls must run on the main thread; these
    decorators marshal via ida_kernwin.execute_sync(). In an idalib worker
    (``IDA_MCP_IDALIB=1``) there is no UI main loop, so the call runs
    inline; the worker serializes SDK access with a lock instead.
"""
from __future__ import annotations

import functools
import inspect
import os
from typing import Any, Callable, TypeVar

try:
    import ida_kernwin  # type: ignore
except ImportError:
    # Allow import outside IDA (e.g. for tests), but decorated functions cannot run
    ida_kernwin = None

try:
    import ida_auto  # type: ignore
except ImportError:
    ida_auto = None

F = TypeVar('F', bound=Callable[..., Any])

def _idalib_mode() -> bool:
    """True inside an idalib worker (no UI main loop to marshal onto)."""
    return os.environ.get("IDA_MCP_IDALIB", "") == "1"

def _run_in_ida(fn: Callable[[], Any], write: bool = False) -> Any:
    """Execute callback in the IDA main thread and return the result."""
    if _idalib_mode() or ida_kernwin is None:
        if ida_kernwin is None and not _idalib_mode():
            raise RuntimeError("ida_kernwin not available (not running in IDA?)")
        return fn()
        
    result_box: dict[str, Any] = {}
    exc_box: dict[str, BaseException] = {}
    
    def wrapper() -> int:
        try:
            result_box["value"] = fn()
        except Exception as e:
            exc_box["error"] = e
        return 0
    
    flag = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
    ida_kernwin.execute_sync(wrapper, flag)
    
    if "error" in exc_box:
        raise exc_box["error"]
    return result_box.get("value")


def idaread(fn: F) -> F:
    """Wrap function for read-only execution in the IDA main thread.

    Usage:
        @tool
        @idaread
        def get_metadata() -> dict:
            # This code runs in the IDA main thread
            return idaapi.get_input_file_path()
    """
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return _run_in_ida(lambda: fn(*args, **kwargs), write=False)
    # Preserve the original function's signature for Pydantic/FastMCP
    wrapper.__signature__ = inspect.signature(fn)  # type: ignore
    wrapper._ida_exec_mode = "read"  # type: ignore[attr-defined]
    return wrapper  # type: ignore


def idawrite(fn: F) -> F:
    """Wrap function for read/write execution in the IDA main thread.

    Usage:
        @tool
        @idawrite
        def set_comment(address: int, comment: str) -> dict:
            # This code runs in the IDA main thread (modifications allowed)
            idaapi.set_cmt(address, comment, 0)
    """
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return _run_in_ida(lambda: fn(*args, **kwargs), write=True)
    # Preserve the original function's signature for Pydantic/FastMCP
    wrapper.__signature__ = inspect.signature(fn)  # type: ignore
    wrapper._ida_exec_mode = "write"  # type: ignore[attr-defined]
    return wrapper  # type: ignore


def run_in_main_thread(fn: Callable[[], Any], write: bool = False) -> Any:
    """Execute a function directly in the IDA main thread (non-decorator form).

    Args:
        fn: Function to execute
        write: Whether write permission is required

    Returns:
        The function's return value
    """
    return _run_in_ida(fn, write=write)


def wait_for_auto_analysis() -> None:
    """Wait for IDA auto-analysis to complete."""
    if ida_auto is None:
        return
    try:
        ida_auto.auto_wait()
    except Exception:
        pass
