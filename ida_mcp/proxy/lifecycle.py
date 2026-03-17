"""Proxy-side lifecycle operations for launching IDA and shutting down the gateway."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from typing import List, Optional

from .. import registry
from ..config import get_ida_default_port, get_ida_path
from ..platform import normalize_subprocess_cwd, wsl_to_win_path
from ._state import forward, get_instances


_RESERVED_LAUNCH_PORTS: dict[int, float] = {}
_RESERVED_LAUNCH_PORTS_LOCK = threading.Lock()
_PORT_RESERVATION_TTL_SECONDS = 180.0
_PORT_SCAN_LIMIT = 512


def _cleanup_reserved_launch_ports(now: Optional[float] = None) -> None:
    """Drop stale or already-registered launch reservations."""
    now = time.monotonic() if now is None else now
    registered_ports = {
        int(instance.get("port"))
        for instance in get_instances()
        if isinstance(instance, dict) and isinstance(instance.get("port"), int)
    }
    stale_ports = [
        port
        for port, reserved_at in _RESERVED_LAUNCH_PORTS.items()
        if port in registered_ports or (now - reserved_at) >= _PORT_RESERVATION_TTL_SECONDS
    ]
    for port in stale_ports:
        _RESERVED_LAUNCH_PORTS.pop(port, None)


def _is_port_bindable(port: int, host: str = "127.0.0.1") -> bool:
    """Return True when a TCP listener can bind to the port right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _reserve_launch_port() -> int:
    """Choose and reserve a port for a soon-to-launch IDA instance."""
    start_port = get_ida_default_port()
    with _RESERVED_LAUNCH_PORTS_LOCK:
        _cleanup_reserved_launch_ports()
        blocked_ports = {
            int(instance.get("port"))
            for instance in get_instances()
            if isinstance(instance, dict) and isinstance(instance.get("port"), int)
        }
        blocked_ports.update(_RESERVED_LAUNCH_PORTS)

        for offset in range(_PORT_SCAN_LIMIT):
            candidate = start_port + offset
            if candidate in blocked_ports:
                continue
            if not _is_port_bindable(candidate):
                continue
            _RESERVED_LAUNCH_PORTS[candidate] = time.monotonic()
            return candidate

    raise RuntimeError(
        f"Failed to reserve an IDA MCP port from {start_port} to {start_port + _PORT_SCAN_LIMIT - 1}"
    )


def _release_launch_port(port: Optional[int]) -> None:
    if port is None:
        return
    with _RESERVED_LAUNCH_PORTS_LOCK:
        _RESERVED_LAUNCH_PORTS.pop(port, None)


def open_in_ida(
    file_path: str,
    extra_args: Optional[List[str]] = None,
) -> dict:
    """Launch interactive IDA and request plugin auto-start."""
    try:
        target_ida = get_ida_path()
        if not target_ida:
            return {"error": "IDA path not configured. Please set IDA_PATH environment variable or 'ida_path' in config.conf."}
        if not os.path.exists(target_ida):
            return {"error": f"IDA executable not found at: {target_ida}"}
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        final_file_path = wsl_to_win_path(os.path.abspath(file_path))
        cmd = [target_ida]
        launch_args = list(extra_args or [])
        if launch_args:
            cmd.extend(launch_args)
        cmd.append(final_file_path)

        reserved_port = _reserve_launch_port()
        env = os.environ.copy()
        env["IDA_MCP_AUTO_START"] = "1"
        env["IDA_MCP_PORT"] = str(reserved_port)
        cwd = normalize_subprocess_cwd(os.path.dirname(target_ida))
        try:
            subprocess.Popen(cmd, cwd=cwd, env=env, close_fds=True if sys.platform != "win32" else False)
        except Exception:
            _release_launch_port(reserved_port)
            raise
        return {
            "status": "ok",
            "message": f"Launched IDA with preferred MCP port {reserved_port}: {' '.join(cmd)}",
            "requested_port": reserved_port,
        }
    except Exception as e:
        return {"error": f"Failed to launch IDA: {e}"}


def close_ida(
    save: bool = True,
    port: Optional[int] = None,
    timeout: Optional[int] = None,
) -> dict:
    """Forward the instance shutdown request to the selected IDA backend."""
    return forward("close_ida", {"save": save}, port, timeout=timeout)


def shutdown_gateway(
    force: bool = False,
    timeout: Optional[int] = None,
) -> dict:
    """Request shutdown of the standalone gateway process."""
    return registry.shutdown_gateway(force=force, timeout=timeout)
