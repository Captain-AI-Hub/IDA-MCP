"""Python 执行转发工具。"""
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
    """注册 Python 执行工具到服务器。"""
    
    @server.tool(description="Execute Python code in IDA context. Returns {result, stdout, stderr}. Has access to all IDA API modules. Supports Jupyter-style evaluation.")
    def py_eval(
        code: Annotated[str, Field(description="Python code to execute")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """在 IDA 上下文中执行 Python 代码。"""
        return forward("py_eval", {"code": code}, port, timeout=timeout)
