"""IDA MCP HTTP 代理服务器 - HTTP 传输入口

直接复用 proxy/_server.py 中的 FastMCP server，只是改为 HTTP 传输方式。

架构:
┌─────────────────────────────────────────────────┐
│              proxy/_server.server               │
│    (FastMCP 实例，唯一的工具定义源)              │
└───────────────┬─────────────────┬───────────────┘
                │                 │
        ┌───────▼───────┐ ┌───────▼───────┐
        │ stdio 传输    │ │ HTTP 传输     │
        │ server.run()  │ │ http_app()    │
        └───────────────┘ └───────────────┘
                │                 │
                └────────┬────────┘
                         ▼
                    协调器 (11337)
                         ▼
                IDA 实例 (10001, ...)
"""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import Optional, Any


class _SessionStickyMiddleware:
    """ASGI middleware: 防止并发请求在 MCP 代理上创建多个 session。

    问题: 当多个并发请求同时到达且都缺少 Mcp-Session-Id 时,
    FastMCP 会为每个请求创建新 session, 最终导致旧 session 被终止。

    方案: 捕获首次响应中的 session ID, 注入到后续缺少该 header 的请求中,
    强制复用同一 session。若服务端返回 404 (session 已终止), 则清除缓存。
    """

    def __init__(self, app):
        self.app = app
        self._session_id: Optional[str] = None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers = list(scope.get("headers", []))

        # 检查请求是否已携带 mcp-session-id
        has_session = any(
            k.lower() == b"mcp-session-id" for k, _ in raw_headers
        )

        # 若缺少且有缓存, 注入 session ID
        if not has_session and self._session_id is not None:
            raw_headers.append(
                (b"mcp-session-id", self._session_id.encode("ascii"))
            )
            scope = {**scope, "headers": raw_headers}

        # 包装 send 以捕获响应中的 session ID
        middleware_self = self

        async def _capture_send(message):
            if message.get("type") == "http.response.start":
                for k, v in message.get("headers", []):
                    if k.lower() == b"mcp-session-id":
                        middleware_self._session_id = v.decode("ascii")
                        break
                # 404 表示 session 已终止, 清除缓存
                if message.get("status") == 404:
                    middleware_self._session_id = None
            await send(message)

        await self.app(scope, receive, _capture_send)

# ============================================================================
# 导入共享的 server
# ============================================================================

# 添加 proxy 目录到路径
_this_dir = os.path.dirname(os.path.abspath(__file__))
_proxy_dir = os.path.join(os.path.dirname(_this_dir), "proxy")
if _proxy_dir not in sys.path:
    sys.path.insert(0, _proxy_dir)

# 导入共享的 server 实例（与 stdio proxy 完全相同）
from _server import server  # type: ignore


# ============================================================================
# 全局状态
# ============================================================================

_http_thread: Optional[threading.Thread] = None
_http_server: Any = None  # uvicorn.Server 实例
_http_port: Optional[int] = None
_stop_lock = threading.Lock()


# ============================================================================
# HTTP 服务器管理
# ============================================================================

def start_http_proxy(host: str = "127.0.0.1", port: int = 11338, path: str = "/mcp") -> bool:
    """启动 HTTP MCP 代理服务器。
    
    参数:
        host: 监听地址
        port: 监听端口
        path: MCP 端点路径
    
    返回:
        是否启动成功
    """
    global _http_thread, _http_server, _http_port
    
    with _stop_lock:
        if _http_thread is not None and _http_thread.is_alive():
            return True  # 已在运行
        
        def worker():
            global _http_server
            try:
                # Windows 控制台噪音抑制
                if os.name == "nt":
                    try:
                        import asyncio
                        if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
                            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                    except Exception:
                        pass
                
                # 使用共享的 server 创建 HTTP app，并包装 session 粘滞中间件
                # 防止并发请求创建多个 MCP session
                app = server.http_app(path=path)
                app = _SessionStickyMiddleware(app)
                
                import uvicorn
                config = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
                _http_server = uvicorn.Server(config)
                
                import asyncio
                
                def _exception_handler(loop, context):
                    exc = context.get("exception")
                    if exc is not None:
                        winerr = getattr(exc, "winerror", None)
                        if winerr == 10054 and isinstance(exc, (ConnectionResetError, OSError)):
                            return
                    msg = str(context.get("message") or "")
                    if "10054" in msg and "ConnectionResetError" in msg:
                        return
                    loop.default_exception_handler(context)
                
                loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(loop)
                    loop.set_exception_handler(_exception_handler)
                    if hasattr(_http_server, "serve"):
                        loop.run_until_complete(_http_server.serve())
                    else:
                        _http_server.run()
                finally:
                    try:
                        loop.run_until_complete(loop.shutdown_asyncgens())
                    except Exception:
                        pass
                    try:
                        loop.run_until_complete(loop.shutdown_default_executor())
                    except Exception:
                        pass
                    try:
                        loop.close()
                    except Exception:
                        pass
            except Exception as e:
                print(f"[IDA-MCP-HTTP][ERROR] Server failed: {e}")
            finally:
                _http_server = None
        
        _http_thread = threading.Thread(target=worker, name="IDA-MCP-HTTP-Proxy", daemon=True)
        _http_thread.start()
        _http_port = port
        
        # 等待服务器启动
        time.sleep(0.5)
        
        return _http_thread.is_alive()


def stop_http_proxy() -> None:
    """停止 HTTP MCP 代理服务器。"""
    global _http_thread, _http_server, _http_port
    
    with _stop_lock:
        if _http_server is not None:
            try:
                _http_server.should_exit = True
            except Exception:
                pass
        
        if _http_thread is not None:
            _http_thread.join(timeout=5)
        
        _http_thread = None
        _http_server = None
        _http_port = None


def is_http_proxy_running() -> bool:
    """检查 HTTP 代理是否正在运行。"""
    return _http_thread is not None and _http_thread.is_alive()


def get_http_url() -> Optional[str]:
    """获取当前 HTTP 代理的 URL。"""
    if _http_port is None:
        return None
    
    # 从配置获取
    try:
        from ..config import get_http_host, get_http_path
        host = get_http_host()
        path = get_http_path()
    except Exception:
        host = "127.0.0.1"
        path = "/mcp"
    
    return f"http://{host}:{_http_port}{path}"


# ============================================================================
# 独立运行入口
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="IDA MCP HTTP Proxy Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=11338, help="Port to bind (default: 11338)")
    parser.add_argument("--path", default="/mcp", help="MCP endpoint path (default: /mcp)")
    args = parser.parse_args()
    
    print(f"[IDA-MCP-HTTP] Starting HTTP proxy at http://{args.host}:{args.port}{args.path}")
    print(f"[IDA-MCP-HTTP] Reusing shared server from proxy/_server.py")
    
    if start_http_proxy(args.host, args.port, args.path):
        print(f"[IDA-MCP-HTTP] Server started successfully")
        try:
            while is_http_proxy_running():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[IDA-MCP-HTTP] Shutting down...")
            stop_http_proxy()
    else:
        print("[IDA-MCP-HTTP] Failed to start server")
        sys.exit(1)
