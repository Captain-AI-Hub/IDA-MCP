"""IDA MCP HTTP proxy transport entrypoint."""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from typing import Any, Optional

from ._server import server


_http_thread: Optional[threading.Thread] = None
_http_server: Any = None
_http_port: Optional[int] = None
_http_host: Optional[str] = None
_http_path: Optional[str] = None
_http_last_error: Optional[str] = None
_stop_lock = threading.Lock()


def _is_http_proxy_listening(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def start_http_proxy(host: str = "127.0.0.1", port: int = 11338, path: str = "/mcp", startup_timeout: float = 5.0) -> bool:
    """Start the HTTP MCP proxy server."""
    global _http_thread, _http_server, _http_port, _http_host, _http_path, _http_last_error

    with _stop_lock:
        if _http_thread is not None and _http_thread.is_alive():
            if _is_http_proxy_listening(host, port):
                _http_last_error = None
                return True

        def worker():
            global _http_server, _http_last_error
            try:
                if os.name == "nt":
                    try:
                        import asyncio

                        if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
                            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                    except Exception:
                        pass

                app = server.http_app(path=path)
                ready = threading.Event()

                import asyncio
                import uvicorn

                config = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
                _http_server = uvicorn.Server(config)
                _http_last_error = None

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

                def _wait_started():
                    try:
                        for _ in range(100):
                            if getattr(_http_server, "started", False):
                                ready.set()
                                return
                            if getattr(_http_server, "should_exit", False):
                                return
                            time.sleep(0.05)
                    except Exception:
                        return

                loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(loop)
                    loop.set_exception_handler(_exception_handler)
                    threading.Thread(target=_wait_started, name="IDA-MCP-HTTP-Ready", daemon=True).start()
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
            except Exception as exc:
                _http_last_error = f"{type(exc).__name__}: {exc}"
                print(f"[IDA-MCP-HTTP][ERROR] Server failed: {exc}")
            finally:
                _http_server = None

        _http_thread = threading.Thread(target=worker, name="IDA-MCP-HTTP-Proxy", daemon=True)
        _http_thread.start()
        _http_host = host
        _http_port = port
        _http_path = path

        deadline = time.monotonic() + max(startup_timeout, 0.5)
        while time.monotonic() < deadline:
            if _is_http_proxy_listening(host, port):
                _http_last_error = None
                return True
            if _http_thread is None or not _http_thread.is_alive():
                break
            time.sleep(0.1)
        if _http_last_error is None:
            _http_last_error = "proxy did not become reachable in time"
        return False


def stop_http_proxy() -> None:
    """Stop the HTTP MCP proxy server."""
    global _http_thread, _http_server, _http_port, _http_host, _http_path

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
        _http_host = None
        _http_path = None


def is_http_proxy_running() -> bool:
    if _http_thread is None or not _http_thread.is_alive() or _http_port is None:
        return False
    host = _http_host or "127.0.0.1"
    return _is_http_proxy_listening(host, _http_port)


def get_http_url() -> Optional[str]:
    if _http_port is None:
        return None

    host = _http_host or "127.0.0.1"
    path = _http_path or "/mcp"

    return f"http://{host}:{_http_port}{path}"


def get_http_proxy_status() -> dict:
    return {
        "running": is_http_proxy_running(),
        "url": get_http_url(),
        "host": _http_host,
        "port": _http_port,
        "path": _http_path,
        "last_error": _http_last_error,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IDA MCP HTTP Proxy Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=11338, help="Port to bind (default: 11338)")
    parser.add_argument("--path", default="/mcp", help="MCP endpoint path (default: /mcp)")
    args = parser.parse_args()

    print(f"[IDA-MCP-HTTP] Starting HTTP proxy at http://{args.host}:{args.port}{args.path}")
    print("[IDA-MCP-HTTP] Reusing shared server from proxy/_server.py")

    if start_http_proxy(args.host, args.port, args.path):
        print("[IDA-MCP-HTTP] Server started successfully")
        try:
            while is_http_proxy_running():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[IDA-MCP-HTTP] Shutting down...")
            stop_http_proxy()
    else:
        print("[IDA-MCP-HTTP] Failed to start server")
        sys.exit(1)
