import os
import socket
import threading
import time
import traceback

from ida_mcp.config import get_server_name, is_unsafe_enabled
from ida_mcp.server_factory import create_mcp_server

_server_thread: threading.Thread | None = None
_uv_server = None  # type: ignore
_startup_thread: threading.Thread | None = None
_startup_stop = threading.Event()
_active_port: int | None = None

_register_with_coordinator_fn = None
_start_tick_thread_fn = None
_start_heartbeat_thread_fn = None
_stop_heartbeat_thread_fn = None
_update_lifecycle_state_fn = None
_ensure_gateway_ready_fn = None


def _now_ts() -> str:
    return time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"


def _log(level: str, msg: str):
    print(f"[IDA-MCP][{level}][{_now_ts()}] {msg}")


def _info(msg: str):
    _log("INFO", msg)


def _warn(msg: str):
    _log("WARN", msg)


def _error(msg: str):
    _log("ERROR", msg)


def configure_runtime_callbacks(
    *,
    register_with_coordinator_fn=None,
    start_tick_thread_fn=None,
    start_heartbeat_thread_fn=None,
    stop_heartbeat_thread_fn=None,
    update_lifecycle_state_fn=None,
    ensure_gateway_ready_fn=None,
) -> None:
    global _register_with_coordinator_fn, _start_tick_thread_fn, _start_heartbeat_thread_fn
    global _stop_heartbeat_thread_fn, _update_lifecycle_state_fn, _ensure_gateway_ready_fn
    if register_with_coordinator_fn is not None:
        _register_with_coordinator_fn = register_with_coordinator_fn
    if start_tick_thread_fn is not None:
        _start_tick_thread_fn = start_tick_thread_fn
    if start_heartbeat_thread_fn is not None:
        _start_heartbeat_thread_fn = start_heartbeat_thread_fn
    if stop_heartbeat_thread_fn is not None:
        _stop_heartbeat_thread_fn = stop_heartbeat_thread_fn
    if update_lifecycle_state_fn is not None:
        _update_lifecycle_state_fn = update_lifecycle_state_fn
    if ensure_gateway_ready_fn is not None:
        _ensure_gateway_ready_fn = ensure_gateway_ready_fn


def get_active_port() -> int | None:
    return _active_port


def get_uv_server():
    return _uv_server


def _wait_for_server_start(ready_event: threading.Event, server_obj) -> None:
    """Wait for uvicorn to set the started flag to True."""
    try:
        for _ in range(100):
            if getattr(server_obj, "started", False):
                ready_event.set()
                return
            if getattr(server_obj, "should_exit", False):
                return
            time.sleep(0.05)
    except Exception:
        return


def _port_is_listening(host: str, port: int, timeout: float = 0.2) -> bool:
    """Check whether the MCP HTTP listener is already accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _complete_startup_in_background(
    host: str,
    port: int,
    server_ready: threading.Event,
    server_failed: threading.Event,
) -> None:
    """Finish registration after the HTTP listener is ready without blocking the UI thread."""
    start_ts = time.monotonic()
    warned_slow = False
    while True:
        if _uv_server is not None and getattr(_uv_server, "should_exit", False):
            return
        if server_ready.is_set() or _port_is_listening(host, port):
            break
        if server_failed.is_set() or not (_server_thread and _server_thread.is_alive()):
            _error(f"Server failed before bind on {host}:{port}")
            return
        if not warned_slow and (time.monotonic() - start_ts) >= 5.0:
            warned_slow = True
            _warn(
                f"Server startup is taking longer than expected on {host}:{port}; registration continues in background."
            )
        time.sleep(0.1)

    global _active_port
    if _active_port == port:
        return
    if _uv_server is not None and getattr(_uv_server, "should_exit", False):
        return
    _info(
        f"Instance MCP listener is ready at http://{host}:{port}/mcp/; registering with gateway."
    )
    if _register_with_coordinator_fn is None or not _register_with_coordinator_fn(port):
        _warn(
            f"Instance MCP server is listening on {host}:{port}, but gateway registration is incomplete."
        )
        return
    _active_port = port
    if _start_tick_thread_fn is not None:
        _start_tick_thread_fn()
    if _start_heartbeat_thread_fn is not None:
        _start_heartbeat_thread_fn()


def _start_instance_server_threads(host: str, port: int) -> None:
    """Launch the instance uvicorn worker only after gateway preflight has passed."""
    global _server_thread, _uv_server
    server_ready = threading.Event()
    server_failed = threading.Event()

    def worker():
        global _uv_server
        try:
            if os.name == "nt":
                try:
                    import asyncio  # type: ignore

                    if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
                        asyncio.set_event_loop_policy(
                            asyncio.WindowsSelectorEventLoopPolicy()
                        )  # type: ignore[attr-defined]
                except Exception:
                    pass
            server = create_mcp_server(
                name=get_server_name(),
                enable_unsafe=is_unsafe_enabled(),
            )
            app = server.http_app(path="/mcp")  # type: ignore[attr-defined]
            import warnings as _w

            _w.filterwarnings("ignore", category=DeprecationWarning, module=r"websockets")
            _w.filterwarnings("ignore", category=DeprecationWarning, module=r"uvicorn")
            import uvicorn

            config = uvicorn.Config(
                app, host=host, port=port, log_level="warning", access_log=False
            )
            _uv_server = uvicorn.Server(config)
            import asyncio

            def _exception_handler(loop, context):  # type: ignore[no-untyped-def]
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
                threading.Thread(
                    target=_wait_for_server_start,
                    args=(server_ready, _uv_server),
                    name="IDA-MCP-ServerReady",
                    daemon=True,
                ).start()
                if hasattr(_uv_server, "serve"):
                    loop.run_until_complete(_uv_server.serve())  # type: ignore[attr-defined]
                else:  # pragma: no cover
                    _uv_server.run()
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
        except Exception as e:  # pragma: no cover
            server_failed.set()
            _error(f"Server crashed: {e}")
            traceback.print_exc()
        finally:
            _uv_server = None
            _info("Server thread exit.")

    _server_thread = threading.Thread(target=worker, name="IDA-MCP-Server", daemon=True)
    _server_thread.start()
    threading.Thread(
        target=_complete_startup_in_background,
        args=(host, port, server_ready, server_failed),
        name="IDA-MCP-StartupFinalize",
        daemon=True,
    ).start()


def is_server_running() -> bool:
    return (_startup_thread is not None and _startup_thread.is_alive()) or (
        _server_thread is not None and _server_thread.is_alive()
    )


def shutdown_server():
    global _startup_thread, _uv_server, _server_thread, _active_port
    startup_thread = _startup_thread
    startup_active = startup_thread is not None and startup_thread.is_alive()
    if _uv_server is None and not startup_active and not (_server_thread and _server_thread.is_alive()):
        return
    if startup_active:
        _startup_stop.set()
        _info("Startup cancellation requested.")
    try:
        if _uv_server is not None:
            _uv_server.should_exit = True  # type: ignore[attr-defined]
            _info("Shutdown signal sent to uvicorn server.")
    except Exception:
        pass
    if startup_thread:
        startup_thread.join(timeout=5)
        if not startup_thread.is_alive():
            _startup_thread = None
    if _server_thread:
        _server_thread.join(timeout=5)
    _server_thread = None
    _uv_server = None
    _active_port = None


def start_instance_server_threads(host: str, port: int) -> None:
    global _startup_thread
    _startup_stop.clear()

    def bootstrap():
        global _startup_thread
        try:
            if _startup_stop.is_set():
                return
            if _ensure_gateway_ready_fn is not None and not _ensure_gateway_ready_fn():
                return
            if _update_lifecycle_state_fn is not None:
                _update_lifecycle_state_fn(port, "analyzing", ready=False)
            if _startup_stop.is_set():
                _info("Startup cancelled before instance MCP listener launch.")
                return
            _info(
                f"Gateway preflight complete; starting instance MCP listener at http://{host}:{port}/mcp/"
            )
            _start_instance_server_threads(host, port)
        finally:
            _startup_thread = None

    _startup_thread = threading.Thread(target=bootstrap, name="IDA-MCP-Startup", daemon=True)
    _startup_thread.start()
