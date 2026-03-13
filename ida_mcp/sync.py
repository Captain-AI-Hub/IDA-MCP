"""IDA 线程同步装饰器。

提供:
    @idaread   - 包装函数在 IDA 主线程只读执行
    @idawrite  - 包装函数在 IDA 主线程读写执行
    
说明:
    所有 IDA SDK 调用必须在主线程执行。这些装饰器通过
    ida_kernwin.execute_sync() 确保线程安全。
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, TypeVar

try:
    import ida_kernwin  # type: ignore
except ImportError:
    # 允许在非 IDA 环境下导入（如测试），但不能执行装饰后的函数
    ida_kernwin = None

try:
    import ida_auto  # type: ignore
except ImportError:
    ida_auto = None

F = TypeVar('F', bound=Callable[..., Any])

def _run_in_ida(fn: Callable[[], Any], write: bool = False) -> Any:
    """在 IDA 主线程执行回调并返回结果。"""
    if ida_kernwin is None:
        raise RuntimeError("ida_kernwin not available (not running in IDA?)")
        
    result_box: dict[str, Any] = {}
    
    def wrapper() -> int:
        try:
            result_box["value"] = fn()
        except Exception as e:
            result_box["error"] = repr(e)
        return 0
    
    flag = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
    ida_kernwin.execute_sync(wrapper, flag)
    
    if "error" in result_box:
        raise RuntimeError(result_box["error"])
    return result_box.get("value")


def idaread(fn: F) -> F:
    """包装函数在 IDA 主线程只读执行。
    
    用法:
        @tool
        @idaread
        def get_metadata() -> dict:
            # 这里的代码会在 IDA 主线程执行
            return idaapi.get_input_file_path()
    """
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return _run_in_ida(lambda: fn(*args, **kwargs), write=False)
    # Preserve the original function's signature for Pydantic/FastMCP
    wrapper.__signature__ = inspect.signature(fn)  # type: ignore
    return wrapper  # type: ignore


def idawrite(fn: F) -> F:
    """包装函数在 IDA 主线程读写执行。
    
    用法:
        @tool
        @idawrite
        def set_comment(address: int, comment: str) -> dict:
            # 这里的代码会在 IDA 主线程执行 (允许修改)
            idaapi.set_cmt(address, comment, 0)
    """
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return _run_in_ida(lambda: fn(*args, **kwargs), write=True)
    # Preserve the original function's signature for Pydantic/FastMCP
    wrapper.__signature__ = inspect.signature(fn)  # type: ignore
    return wrapper  # type: ignore


def run_in_main_thread(fn: Callable[[], Any], write: bool = False) -> Any:
    """直接在 IDA 主线程执行函数 (非装饰器形式)。
    
    参数:
        fn: 要执行的函数
        write: 是否需要写权限
    
    返回:
        函数返回值
    """
    return _run_in_ida(fn, write=write)


def wait_for_auto_analysis() -> None:
    """等待 IDA 自动分析完成。"""
    if ida_auto is None:
        return
    try:
        ida_auto.auto_wait()
    except Exception:
        pass
