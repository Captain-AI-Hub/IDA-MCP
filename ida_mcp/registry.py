"""Client helpers for the standalone gateway service."""

from __future__ import annotations

import atexit
import json
import ntpath
import os
import tempfile
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .config import (
    get_http_bind_host,
    get_ida_python,
    get_gateway_internal_host,
    get_gateway_internal_port,
    get_gateway_internal_url,
    get_http_path,
    get_http_port,
    get_request_timeout,
    is_http_enabled,
    is_stdio_enabled,
)


_registry_start_lock = threading.Lock()
_http_proxy_start_lock = threading.Lock()
_self_pid = os.getpid()
_deregister_registered = False
_launch_status: Dict[str, Dict[str, Any]] = {
    "registry_server": {},
    "http_proxy": {},
}

from .utils import display_path as _display_path


def _gateway_internal_alive(timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection(
            (get_gateway_internal_host(), get_gateway_internal_port()), timeout=timeout
        ):
            return True
    except OSError:
        return False


def _http_proxy_alive(timeout: float = 0.3) -> bool:
    status = _request_json("GET", "/proxy_status", timeout=timeout, ensure_server=False)
    return bool(isinstance(status, dict) and status.get("running"))


def _gateway_ready(timeout: float = 0.5) -> bool:
    status = _request_json("GET", "/healthz", timeout=timeout, ensure_server=False)
    return bool(isinstance(status, dict) and status.get("ok"))


def _wait_for_gateway_ready(timeout: float) -> bool:
    """Poll the health endpoint until the gateway becomes ready or times out."""
    deadline = time.monotonic() + max(timeout, 0.0)
    while time.monotonic() < deadline:
        if _gateway_ready():
            return True
        time.sleep(0.1)
    return _gateway_ready()


def _launch_log_path(name: str) -> str:
    return os.path.join(tempfile.gettempdir(), f"ida_mcp_{name}.log")


def _set_launch_status(name: str, **fields: Any) -> None:
    status = dict(_launch_status.get(name, {}))
    status.update(fields)
    _launch_status[name] = status


def _tail_log_line(path: str | None) -> str | None:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = [line.strip() for line in handle.readlines() if line.strip()]
        return lines[-1] if lines else None
    except Exception:
        return None


def _spawn_detached(args: List[str], cwd: str, log_path: Optional[str] = None) -> None:
    log_handle = None
    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        log_handle = open(log_path, "ab")
    kwargs: Dict[str, Any] = {
        "cwd": cwd,
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle if log_handle is not None else subprocess.DEVNULL,
        "stderr": log_handle if log_handle is not None else subprocess.DEVNULL,
        "close_fds": True if os.name != "nt" else False,
    }
    if os.name == "nt":
        creationflags = 0
        creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kwargs["creationflags"] = creationflags
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen(args, **kwargs)
    finally:
        if log_handle is not None:
            log_handle.close()


def _is_python_executable(path: str | None) -> bool:
    if not path:
        return False
    path_mod = (
        ntpath if ("\\" in path or (len(path) > 1 and path[1] == ":")) else os.path
    )
    name = path_mod.basename(path).lower()
    return name.startswith("python")


def _candidate_python_executables() -> List[str]:
    candidates: List[str] = []

    configured_python = get_ida_python()
    if configured_python:
        candidates.append(configured_python)

    for value in (
        getattr(sys, "executable", None),
        getattr(sys, "_base_executable", None),
    ):
        if value:
            candidates.append(value)

    def add_candidates_near_root(root: str | None) -> None:
        if not root:
            return
        path_mod = (
            ntpath if ("\\" in root or (len(root) > 1 and root[1] == ":")) else os.path
        )
        if path_mod is ntpath or os.name == "nt":
            candidates.extend(
                [
                    path_mod.join(root, "python.exe"),
                    path_mod.join(root, "ida-python", "python.exe"),
                    path_mod.join(root, "python", "python.exe"),
                    path_mod.join(root, "Scripts", "python.exe"),
                ]
            )
        else:
            candidates.extend(
                [
                    path_mod.join(root, "bin", "python3"),
                    path_mod.join(root, "bin", "python"),
                    path_mod.join(root, "ida-python", "python3"),
                    path_mod.join(root, "ida-python", "python"),
                    path_mod.join(root, "python", "bin", "python3"),
                    path_mod.join(root, "python", "bin", "python"),
                ]
            )

    current_exe = getattr(sys, "executable", "") or ""
    path_mod = (
        ntpath
        if ("\\" in current_exe or (len(current_exe) > 1 and current_exe[1] == ":"))
        else os.path
    )
    current_dir = path_mod.dirname(current_exe)
    add_candidates_near_root(current_dir)

    for value in (
        getattr(sys, "prefix", None),
        getattr(sys, "base_prefix", None),
        getattr(sys, "exec_prefix", None),
    ):
        add_candidates_near_root(value)

    for name in ["python.exe"] if os.name == "nt" else ["python3", "python"]:
        resolved = shutil.which(name)
        if resolved:
            candidates.append(resolved)

    seen = set()
    ordered: List[str] = []
    for candidate in candidates:
        key = candidate.lower() if os.name == "nt" else candidate
        if key in seen:
            continue
        seen.add(key)
        ordered.append(candidate)
    return ordered


def _resolve_python_executable() -> str:
    for candidate in _candidate_python_executables():
        if not os.path.isfile(candidate):
            continue
        if _is_python_executable(candidate):
            return candidate
    raise RuntimeError(
        "No standalone Python interpreter found for gateway launch. "
        "Configure ida_python to a python executable."
    )


def _package_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _repo_root() -> str:
    return os.path.dirname(_package_dir())


def ensure_registry_server(startup_timeout: float = 3.0) -> bool:
    """Ensure the standalone single-port gateway is reachable."""
    if _gateway_ready():
        return True

    with _registry_start_lock:
        if _gateway_ready():
            return True
        log_path = _launch_log_path("registry_server")
        _set_launch_status(
            "registry_server",
            requested=True,
            log=log_path,
            alive=False,
            last_error=None,
        )

        # A listener already exists on the target port. Give it a chance to finish
        # booting into a healthy gateway, but do not spawn a second process.
        if _gateway_internal_alive():
            if _wait_for_gateway_ready(max(startup_timeout, 0.5)):
                _set_launch_status("registry_server", alive=True, last_error=None)
                return True
            _set_launch_status(
                "registry_server",
                alive=False,
                last_error=(
                    f"Port {get_gateway_internal_port()} is already listening on {get_gateway_internal_host()} "
                    "but did not respond as a healthy IDA-MCP gateway."
                ),
            )
            return False

        python_exe = _resolve_python_executable()
        _set_launch_status(
            "registry_server",
            python=python_exe,
        )
        _spawn_detached(
            [
                python_exe,
                "-m",
                "ida_mcp.registry_server",
                "--host",
                get_http_bind_host(),
                "--port",
                str(get_gateway_internal_port()),
            ],
            cwd=_repo_root(),
            log_path=log_path,
        )

        if _wait_for_gateway_ready(max(startup_timeout, 8.0)):
            _set_launch_status("registry_server", alive=True, last_error=None)
            return True
        _set_launch_status(
            "registry_server",
            alive=False,
            last_error=_tail_log_line(log_path)
            or "gateway did not become reachable in time",
        )
        return False


def ensure_http_proxy_running(startup_timeout: float = 3.0) -> bool:
    """Ensure the merged gateway process has brought the HTTP proxy online."""
    if not is_http_enabled():
        _set_launch_status("http_proxy", requested=False, enabled=False, alive=False)
        return False
    if _http_proxy_alive():
        _set_launch_status(
            "http_proxy",
            requested=True,
            enabled=True,
            alive=True,
            python=_launch_status.get("http_proxy", {}).get("python"),
            log=_launch_status.get("http_proxy", {}).get("log"),
            last_error=None,
        )
        return True

    with _http_proxy_start_lock:
        if _http_proxy_alive():
            _set_launch_status(
                "http_proxy", requested=True, enabled=True, alive=True, last_error=None
            )
            return True

        if not ensure_registry_server():
            _set_launch_status(
                "http_proxy",
                requested=True,
                enabled=True,
                alive=False,
                python=_launch_status.get("registry_server", {}).get("python"),
                log=_launch_status.get("registry_server", {}).get("log"),
                last_error="gateway not reachable",
            )
            return False

        gateway_status = dict(_launch_status.get("registry_server", {}))
        log_path = gateway_status.get("log") or _launch_log_path("registry_server")
        _set_launch_status(
            "http_proxy",
            requested=True,
            enabled=True,
            python=gateway_status.get("python"),
            log=log_path,
            alive=False,
            last_error=None,
        )

        status = _request_json(
            "POST", "/ensure_proxy", {}, timeout=1.0, ensure_server=False
        )
        if isinstance(status, dict):
            _set_launch_status(
                "http_proxy",
                enabled=bool(status.get("enabled", True)),
                alive=bool(status.get("running", False)),
                log=log_path,
                last_error=status.get("last_error"),
            )

        deadline = time.monotonic() + max(startup_timeout, 8.0)
        while time.monotonic() < deadline:
            if _http_proxy_alive():
                _set_launch_status("http_proxy", alive=True, last_error=None)
                return True
            time.sleep(0.1)
        status = _request_json("GET", "/proxy_status", ensure_server=False)
        last_error = None
        if isinstance(status, dict):
            last_error = status.get("last_error")
        _set_launch_status(
            "http_proxy",
            alive=False,
            last_error=last_error or "http proxy did not become reachable in time",
        )
        return False


def _request_json(
    method: str,
    path: str,
    payload: Optional[dict] = None,
    timeout: Optional[float] = None,
    ensure_server: bool = True,
) -> Any:
    if ensure_server and not _gateway_ready() and not ensure_registry_server():
        return None

    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        get_gateway_internal_url() + path,
        data=data,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(
            req, timeout=get_request_timeout() if timeout is None else timeout
        ) as resp:
            return json.loads(resp.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8") or "null")
        except Exception:
            return None
    except Exception:
        return None


def _register_atexit_once() -> None:
    global _deregister_registered
    if _deregister_registered:
        return
    atexit.register(deregister)
    _deregister_registered = True


def _format_registry_server_failure() -> str:
    """Build a concise diagnostic string for gateway launch failures."""
    status = get_registry_server_status()
    parts = [
        f"python={_display_path(status.get('python') or _resolve_python_executable())}",
    ]
    log_path = status.get("log") or _launch_log_path("registry_server")
    parts.append(f"log={_display_path(log_path)}")
    if status.get("last_error"):
        parts.append(f"last_error={status['last_error']}")
    return ", ".join(parts)


def _register_instance_payload(
    pid: int,
    port: int,
    input_file: str | None,
    idb_path: str | None,
    *,
    ready: bool,
    lifecycle_state: str,
    started: Optional[float] = None,
) -> dict[str, Any]:
    return {
        "pid": pid,
        "port": port,
        "host": "127.0.0.1",
        "input_file": input_file,
        "idb": idb_path,
        "started": time.time() if started is None else started,
        "python": sys.version.split()[0],
        "ready": bool(ready),
        "lifecycle_state": lifecycle_state,
    }


def register_pending_instance(
    pid: int,
    port: int,
    input_file: str | None,
    idb_path: str | None,
    *,
    lifecycle_state: str = "starting",
) -> bool:
    """Register a launched-but-not-ready IDA process with the gateway."""
    if not is_stdio_enabled() and not is_http_enabled():
        return False
    if not ensure_registry_server():
        return False
    payload = _register_instance_payload(
        pid,
        port,
        input_file,
        idb_path,
        ready=False,
        lifecycle_state=lifecycle_state,
    )
    result = _request_json(
        "POST", "/register", payload, timeout=0.5, ensure_server=False
    )
    return isinstance(result, dict) and result.get("status") == "ok"


def update_instance_status(
    *,
    pid: Optional[int] = None,
    port: Optional[int] = None,
    lifecycle_state: Optional[str] = None,
    ready: Optional[bool] = None,
    main_thread_last_tick_at: Optional[float] = None,
    main_thread_lag_seconds: Optional[float] = None,
) -> bool:
    """Apply a partial status update to a registered instance."""
    if pid is None and port is None:
        return False
    if not ensure_registry_server():
        return False
    payload: dict[str, Any] = {}
    if pid is not None:
        payload["pid"] = pid
    if port is not None:
        payload["port"] = port
    if lifecycle_state is not None:
        payload["lifecycle_state"] = lifecycle_state
    if ready is not None:
        payload["ready"] = bool(ready)
    if main_thread_last_tick_at is not None:
        payload["main_thread_last_tick_at"] = float(main_thread_last_tick_at)
    if main_thread_lag_seconds is not None:
        payload["main_thread_lag_seconds"] = float(main_thread_lag_seconds)
    result = _request_json(
        "POST", "/update_instance", payload, timeout=0.5, ensure_server=False
    )
    return isinstance(result, dict) and result.get("status") == "ok"


def init_and_register(port: int, input_file: str | None, idb_path: str | None) -> None:
    """Register the current IDA instance with the standalone gateway."""
    if not is_stdio_enabled() and not is_http_enabled():
        return
    if not ensure_registry_server():
        raise RuntimeError(
            f"Gateway not reachable at {get_gateway_internal_host()}:{get_gateway_internal_port()} "
            f"({_format_registry_server_failure()})"
        )

    payload = _register_instance_payload(
        _self_pid,
        port,
        input_file,
        idb_path,
        ready=True,
        lifecycle_state="ready",
    )

    for _ in range(10):
        result = _request_json(
            "POST", "/register", payload, timeout=0.5, ensure_server=False
        )
        if isinstance(result, dict) and result.get("status") == "ok":
            _register_atexit_once()
            return
        if not _gateway_internal_alive() and not ensure_registry_server():
            break
        time.sleep(0.1)

    raise RuntimeError(
        f"Failed to register instance on gateway {get_gateway_internal_host()}:{get_gateway_internal_port()} "
        f"({_format_registry_server_failure()})"
    )


def get_instances() -> List[Dict[str, Any]]:
    """Return registered instances from the standalone gateway."""
    data = _request_json("GET", "/instances")
    return data if isinstance(data, list) else []


def deregister() -> bool:  # pragma: no cover
    result = _request_json(
        "POST",
        "/deregister",
        {"pid": _self_pid},
        timeout=0.5,
        ensure_server=False,
    )
    return isinstance(result, dict) and result.get("status") == "ok"


def check_connection() -> dict:
    instances = get_instances()
    return {"ok": _gateway_ready(), "count": len(instances)}


def shutdown_gateway(force: bool = False, timeout: Optional[float] = None) -> dict:
    """Request a graceful gateway shutdown via the internal control API."""
    result = _request_json(
        "POST",
        "/shutdown",
        {"force": bool(force)},
        timeout=timeout,
        ensure_server=False,
    )
    return result if isinstance(result, dict) else {"error": "Gateway unavailable"}


def get_http_proxy_status() -> dict:
    status = _request_json("GET", "/proxy_status", ensure_server=False)
    merged = dict(_launch_status.get("http_proxy", {}))
    if isinstance(status, dict):
        merged.update(
            {
                "enabled": status.get("enabled", is_http_enabled()),
                "alive": status.get("running", _http_proxy_alive()),
                "url": status.get("url"),
                "host": status.get("host"),
                "port": status.get("port"),
                "path": status.get("path"),
                "last_error": status.get("last_error") or merged.get("last_error"),
            }
        )
    else:
        merged["alive"] = _http_proxy_alive()
        merged.setdefault("enabled", is_http_enabled())
    return merged


def get_registry_server_status() -> dict:
    status = dict(_launch_status.get("registry_server", {}))
    status["alive"] = _gateway_ready()
    return status
