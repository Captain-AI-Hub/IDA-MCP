"""IDA MCP 代理 (协调器客户端) - stdio 传输入口

使用 stdio 传输的 MCP 服务器，通过协调器访问多个 IDA 实例。

架构
====================
proxy/
├── __init__.py           # 模块导出
├── _server.py            # 共享的 FastMCP server (stdio/HTTP 复用)
├── ida_mcp_proxy.py      # stdio 传输入口 (本文件)
├── _http.py              # HTTP 辅助函数
├── _state.py             # 状态管理和实例选择
├── proxy_core.py         # 核心工具: list_functions, metadata, strings
├── proxy_analysis.py     # 分析工具: decompile, disasm, xrefs
├── proxy_modify.py       # 修改工具: comment, rename
├── proxy_memory.py       # 内存工具: read_bytes, read_string
├── proxy_types.py        # 类型工具: set_func_type, declare_type
├── proxy_debug.py        # 调试工具: dbg_*
└── proxy_stack.py        # 栈帧工具: stack_frame

使用方式
====================
直接运行: python ida_mcp_proxy.py
或模块运行: python -m ida_mcp.proxy.ida_mcp_proxy
"""
from __future__ import annotations

import sys
import os
from typing import Any

# 支持直接运行和作为包导入两种方式
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

# 导入共享的 server 实例（包含所有工具定义）
from _server import server  # type: ignore


# ============================================================================
# 入口 - stdio 传输
# ============================================================================

if __name__ == "__main__":
    import signal
    
    def _signal_handler(sig: int, frame: Any) -> None:
        """优雅退出。"""
        sys.exit(0)
    
    # 注册信号处理 (Windows 只支持 SIGINT)
    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, _signal_handler)
    
    try:
        server.run(show_banner=False)
    except KeyboardInterrupt:
        pass  # 静默退出
