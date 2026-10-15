"""Bridge lifecycle inside an IDA process.

Starts the stdlib JSON-RPC bridge, publishes the instance in the shared
JSON registry, and keeps the cached metadata (input/idb paths) fresh. There
is no gateway, no port registration protocol, and no third-party dependency
inside IDA anymore.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from typing import Any, Dict, Optional

from ida_mcp import bridge_server
from ida_mcp.bridge_server import BRIDGE_HOST, BRIDGE_PORT_BASE
from ida_mcp.config import is_debug_enabled

_stop_lock = threading.Lock()
_bridge: Optional[bridge_server.BridgeServer] = None
_host_prime_paths = None
_path_cache: Dict[str, Any] = {"input_file": None, "idb_path": None}
_touch_thread: Optional[threading.Thread] = None
_touch_stop = threading.Event()

_TOUCH_INTERVAL = 30.0


def _now_ts() -> str:
    return time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"


def _log(level: str, msg: str):
    print(f"[IDA-MCP][{level}][{_now_ts()}] {msg}")


def _info(msg: str):
    _log("INFO", msg)


def _warn(msg: str):
    _log("WARN", msg)


def register_host_callbacks(*, prime_paths_fn=None):
    """Wire the plugin entry file's main-thread path collector."""
    global _host_prime_paths
    if prime_paths_fn is not None:
        _host_prime_paths = prime_paths_fn


def set_path_cache(input_file, idb_path):
    _path_cache["input_file"] = input_file
    _path_cache["idb_path"] = idb_path


def get_path_cache():
    return _path_cache.get("input_file"), _path_cache.get("idb_path")


def _prime_path_caches() -> None:
    if _host_prime_paths is not None:
        try:
            _host_prime_paths()
        except Exception as exc:  # noqa: BLE001 - path priming is best effort
            _warn(f"prime path caches failed: {exc}")
        return
    try:
        from ida_mcp.sync import run_in_main_thread

        def _read():
            import ida_nalt  # type: ignore
            import ida_loader  # type: ignore

            set_path_cache(
                ida_nalt.get_input_file_path() or "",
                ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
            )

        run_in_main_thread(_read)
    except Exception as exc:  # noqa: BLE001
        _warn(f"prime path caches failed: {exc}")


def _collect_meta() -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "version": bridge_server_version(),
    }
    try:
        from ida_mcp.sync import run_in_main_thread

        def _read():
            import ida_nalt  # type: ignore
            import ida_loader  # type: ignore
            import idaapi  # type: ignore

            return {
                "input_file": ida_nalt.get_input_file_path() or "",
                "database_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
                "ida_version": idaapi.get_kernel_version() or "",
            }

        meta.update(run_in_main_thread(_read) or {})
    except Exception:  # noqa: BLE001 - metadata must never crash the bridge
        input_file, idb_path = get_path_cache()
        meta.setdefault("input_file", input_file or "")
        meta.setdefault("database_path", idb_path or "")
    return meta


def bridge_server_version() -> str:
    from ida_mcp import __version__

    return __version__


def _find_free_port(preferred: int, host: str = "127.0.0.1", max_scan: int = 50) -> int:
    """Try binding upward from preferred and return the first free port."""
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
    """Select a bindable bridge port, treating bootstrap IDA_MCP_PORT as preferred."""
    env_port = os.getenv("IDA_MCP_PORT")
    if env_port and env_port.isdigit():
        return _find_free_port(int(env_port), host)
    return _find_free_port(BRIDGE_PORT_BASE, host)


def _start_touch_thread() -> None:
    """Periodically refresh last_seen_at in the shared registry."""

    def _loop():
        while not _touch_stop.wait(_TOUCH_INTERVAL):
            bridge = _bridge
            if bridge is None:
                return
            try:
                from ida_mcp import instances

                instances.touch_instance(bridge.instance_id)
            except Exception:  # noqa: BLE001 - keep-alive is best effort
                pass

    global _touch_thread
    if _touch_thread is not None and _touch_thread.is_alive():
        return
    _touch_stop.clear()
    _touch_thread = threading.Thread(
        target=_loop, name="IDA-MCP-Touch", daemon=True
    )
    _touch_thread.start()


def is_running() -> bool:
    return _bridge is not None


def get_bridge() -> Optional[bridge_server.BridgeServer]:
    return _bridge


def start_server_async(host: Optional[str] = None, port: Optional[int] = None):
    """Start the bridge in a background thread (returns immediately)."""
    if is_running():
        _info("Bridge already running; start request ignored.")
        return

    bind_host = host or BRIDGE_HOST
    bind_port = port or _select_start_port(bind_host)

    def _run():
        global _bridge
        _prime_path_caches()
        try:
            server = bridge_server.BridgeServer(
                host=bind_host,
                port=bind_port,
                headless=False,
                get_meta=_collect_meta,
            )
            actual_port = server.start()
        except OSError as exc:
            _warn(f"Failed to bind bridge on {bind_host}:{bind_port}: {exc}")
            return
        _bridge = server
        input_file, idb_path = get_path_cache()
        _info(
            f"Bridge listening on {bind_host}:{actual_port} "
            f"(instance {server.instance_id}, pid {os.getpid()})"
        )
        _info(f"input='{input_file}' idb='{idb_path}'")
        if is_debug_enabled():
            os.environ.setdefault("IDA_MCP_DEBUG", "1")
        _start_touch_thread()

    threading.Thread(target=_run, name="IDA-MCP-Startup", daemon=True).start()


def stop_server():
    """Stop the bridge and remove the registry entry."""
    global _bridge, _touch_thread
    with _stop_lock:
        bridge, _bridge = _bridge, None
        _touch_stop.set()
        thread, _touch_thread = _touch_thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=1)
        if bridge is None:
            return
        try:
            bridge.stop()
            _info("Bridge stopped.")
        except Exception as exc:  # noqa: BLE001 - shutdown is best effort
            _warn(f"Bridge stop failed: {exc}")
