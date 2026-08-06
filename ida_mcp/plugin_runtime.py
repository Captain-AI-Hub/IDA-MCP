import os
import socket
import threading
import time
import traceback

from ida_mcp import registry
from ida_mcp import heartbeat as _heartbeat
from ida_mcp import instance_server as _instance_server
from ida_mcp.config import (
    get_gateway_internal_host,
    get_gateway_internal_port,
    get_http_bind_host,
    get_http_path,
    get_http_port,
    get_ida_default_port,
    get_request_timeout,
    is_gateway_enabled,
)
from ida_mcp.heartbeat import (
    clear_main_thread_tick,
    configure_state_getters,
    get_path_cache,
    reset_heartbeat_failure_tracking,
    set_main_thread_tick as _hb_set_main_thread_tick,
    set_path_cache as _hb_set_path_cache,
    start_heartbeat_thread,
    stop_heartbeat_thread,
)
from ida_mcp.instance_server import (
    configure_runtime_callbacks,
    get_active_port,
    get_uv_server,
    is_server_running as _instance_server_running,
    shutdown_server as _instance_shutdown_server,
    start_instance_server_threads,
)
from ida_mcp.runtime import start_gateway_proxy_if_enabled

_stop_lock = threading.Lock()
_tick_thread: threading.Thread | None = None
_tick_stop_event = threading.Event()
_host_tick_fn = None
_host_prime_paths = None


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


def register_host_callbacks(*, tick_loop_fn=None, prime_paths_fn=None):
    global _host_tick_fn, _host_prime_paths
    if tick_loop_fn is not None:
        _host_tick_fn = tick_loop_fn
    if prime_paths_fn is not None:
        _host_prime_paths = prime_paths_fn


def set_path_cache(input_file, idb_path):
    _hb_set_path_cache(input_file, idb_path)


def set_main_thread_tick(ts=None):
    _hb_set_main_thread_tick(ts)


def start_tick_thread() -> None:
    global _tick_thread
    set_main_thread_tick()
    if _tick_thread is not None and _tick_thread.is_alive():
        return
    _tick_stop_event.clear()
    if _host_tick_fn is None:
        return
    _tick_thread = threading.Thread(
        target=_host_tick_fn,
        name="IDA-MCP-MainThreadTick",
        daemon=True,
    )
    _tick_thread.start()


def _gateway_diagnostics_text() -> str:
    """Summarize gateway launch diagnostics for IDA main-log output."""
    status_getter = getattr(registry, "get_registry_server_status", None)
    if not callable(status_getter):
        return ""
    try:
        status = status_getter() or {}
    except Exception:
        return ""
    if not isinstance(status, dict):
        return ""

    parts = []
    if status.get("python"):
        parts.append(f"python={status['python']}")
    if status.get("log"):
        parts.append(f"log={status['log']}")
    if status.get("last_error"):
        parts.append(f"last_error={status['last_error']}")
    return ", ".join(parts)


def _find_free_port(preferred: int, host: str = "127.0.0.1", max_scan: int = 50) -> int:
    """Port scan: try binding upward from preferred and return the first free port.

    Note: default port starts at 9000 to avoid the Windows Hyper-V reserved port range.
    """
    for i in range(max_scan):
        p = preferred + i
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
            except OSError:
                continue
            return p
    _warn(f"Port scan exhausted; falling back to preferred {preferred}")
    return preferred


def _select_start_port(host: str) -> int:
    """Select a bindable MCP port, treating bootstrap IDA_MCP_PORT as a preferred starting point."""
    env_port = os.getenv("IDA_MCP_PORT")
    if env_port and env_port.isdigit():
        return _find_free_port(int(env_port), host)
    return _find_free_port(get_ida_default_port(), host)


def _ensure_gateway_ready_for_startup() -> bool:
    """Confirm the standalone gateway is healthy before exposing the instance listener."""
    gateway_host = get_gateway_internal_host()
    gateway_port = get_gateway_internal_port()
    startup_timeout = max(float(get_request_timeout()), 8.0)
    _info(
        f"Checking gateway health at {gateway_host}:{gateway_port} before starting "
        f"instance MCP listener (timeout={startup_timeout:.0f}s)."
    )
    if registry.ensure_registry_server(startup_timeout=startup_timeout):
        _info(
            f"Gateway is healthy at {gateway_host}:{gateway_port}; continuing instance startup."
        )
        return True

    _error(
        f"Gateway preflight failed at {gateway_host}:{gateway_port}; instance MCP listener will not be started."
    )
    diag = _gateway_diagnostics_text()
    if diag:
        _error(f"Gateway diagnostics: {diag}")
    return False


def _register_with_gateway(port: int) -> bool:
    """Register the current instance metadata with the gateway."""
    if _host_prime_paths:
        _host_prime_paths()
    cached_input_file, cached_idb_path = get_path_cache()
    try:
        registry.init_and_register(port, cached_input_file, cached_idb_path)
        gateway_proxy_ready = start_gateway_proxy_if_enabled()
        reset_heartbeat_failure_tracking()
        _info(
            f"Registered instance at port={port} pid={os.getpid()} input='{cached_input_file}' idb='{cached_idb_path}'"
        )
        if gateway_proxy_ready:
            _info(
                f"HTTP MCP proxy listening on http://{get_http_bind_host()}:{get_http_port()}{get_http_path()}"
            )
        elif is_gateway_enabled():
            gateway_proxy_status = getattr(registry, "get_gateway_proxy_status", lambda: {})()
            if not isinstance(gateway_proxy_status, dict):
                gateway_proxy_status = {}
            status_parts = []
            if gateway_proxy_status.get("python"):
                status_parts.append(f"python={gateway_proxy_status['python']}")
            if gateway_proxy_status.get("log"):
                status_parts.append(f"log={gateway_proxy_status['log']}")
            if gateway_proxy_status.get("last_error"):
                status_parts.append(f"last_error={gateway_proxy_status['last_error']}")
            suffix = f" ({', '.join(status_parts)})" if status_parts else ""
            _warn(f"Gateway MCP proxy launch requested but not yet reachable{suffix}")
        gateway_suffix = get_http_path() if is_gateway_enabled() else ""
        _info(
            f"Gateway listening on {get_http_bind_host()}:{get_http_port()}{gateway_suffix}"
        )
        return True
    except Exception as e:  # pragma: no cover
        _error(f"Gateway registration failed: {e}")
        diag = _gateway_diagnostics_text()
        if diag:
            _error(f"Gateway diagnostics: {diag}")
        traceback.print_exc()
        return False


def _update_lifecycle_state(port: int, state: str, ready: bool) -> None:
    try:
        registry.update_instance_status(
            pid=os.getpid(),
            port=port,
            lifecycle_state=state,
            ready=ready,
        )
    except Exception:
        pass


def is_running() -> bool:
    return _instance_server_running()


def stop_server():
    """Stop the server (toggle)."""
    with _stop_lock:
        startup_running = _instance_server_running()
        if not startup_running:
            _info("Stop requested, but server not running.")
            return

        active_port = get_active_port()
        try:
            _instance_shutdown_server()
        finally:
            stop_heartbeat_thread()
            global _tick_thread, _tick_stop_event
            if _tick_thread and _tick_thread.is_alive():
                _tick_stop_event.set()
                _tick_thread.join(timeout=1)
            _tick_thread = None
            clear_main_thread_tick()
            if active_port is not None:
                try:
                    registry.deregister()
                except Exception as e:  # pragma: no cover
                    _warn(f"Deregister failed: {e}")
            reset_heartbeat_failure_tracking()
            _info("Server stopped.")


def start_server_async(host: str, port: int):
    """Asynchronously (in a thread) start the uvicorn FastMCP service."""
    if is_running():
        _info("Server already running; start request ignored.")
        return
    start_instance_server_threads(host, port)


configure_state_getters(active_port_getter=get_active_port, uv_server_getter=get_uv_server)
configure_runtime_callbacks(
    register_with_gateway_fn=_register_with_gateway,
    start_tick_thread_fn=start_tick_thread,
    start_heartbeat_thread_fn=start_heartbeat_thread,
    stop_heartbeat_thread_fn=stop_heartbeat_thread,
    update_lifecycle_state_fn=_update_lifecycle_state,
    ensure_gateway_ready_fn=_ensure_gateway_ready_for_startup,
)


_LEGACY_HEARTBEAT_ATTRS = {
    "_MAIN_THREAD_TICK_INTERVAL",
    "_cached_input_file",
    "_cached_idb_path",
}
_LEGACY_INSTANCE_SERVER_ATTRS = {
    "_server_thread",
    "_startup_thread",
}


def __getattr__(name: str):
    """Resolve legacy module attributes from their current owner modules."""
    if name in _LEGACY_HEARTBEAT_ATTRS:
        return getattr(_heartbeat, name)
    if name in _LEGACY_INSTANCE_SERVER_ATTRS:
        return getattr(_instance_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
