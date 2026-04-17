"""IDA MCP 代理 (协调器客户端) - stdio 传输入口

使用 stdio 传输的 MCP 服务器，通过协调器访问多个 IDA 实例。

架构
====================
proxy/
├── __init__.py           # 模块导出
├── _server.py            # 共享的 FastMCP server (stdio/HTTP 复用)
├── lifecycle.py          # proxy 侧生命周期操作
├── register_tools.py     # 集中注册所有转发工具
├── ida_mcp_proxy.py      # stdio 传输入口 (本文件)
├── _http.py              # HTTP 辅助函数
├── _state.py             # 状态管理和实例选择
└── http_server.py        # HTTP 传输入口

使用方式
====================
直接运行: python ida_mcp_proxy.py
或模块运行: python -m ida_mcp.proxy.ida_mcp_proxy
"""
from __future__ import annotations

import pathlib
import sys
from typing import Any

if __package__ in {None, ""}:
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from ida_mcp.proxy._server import server
else:
    from ._server import server


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
