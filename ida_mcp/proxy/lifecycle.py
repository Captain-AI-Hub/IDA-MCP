"""Proxy-side lifecycle operations for launching IDA and shutting down the gateway."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import List, Optional

from .. import registry
from ..config import (
    get_ida_default_port,
    get_ida_path,
    get_ida_python,
    get_open_in_ida_bundle_dir,
    is_open_in_ida_autonomous_enabled,
    is_wsl_path_bridge_enabled,
)
from ._state import forward, get_instances


_RESERVED_LAUNCH_PORTS: dict[int, float] = {}
_RESERVED_LAUNCH_PORTS_LOCK = threading.Lock()
_PORT_RESERVATION_TTL_SECONDS = 180.0
_PORT_SCAN_LIMIT = 512
_LAUNCH_BUNDLE_ROOT = "ida_mcp_open"


def _looks_like_windows_drive_path(path: str) -> bool:
    candidate = str(path).strip()
    return (
        len(candidate) >= 3
        and candidate[0].isalpha()
        and candidate[1] == ":"
        and candidate[2] in {"\\", "/"}
    )


def _looks_like_wsl_mount_path(path: str) -> bool:
    candidate = str(path).strip().replace("\\", "/")
    return (
        candidate.startswith("/mnt/")
        and len(candidate) >= 6
        and candidate[5].isalpha()
        and (len(candidate) == 6 or candidate[6] == "/")
    )


def _windows_to_wsl_path(path: str) -> Optional[str]:
    candidate = str(path).strip()
    if not _looks_like_windows_drive_path(candidate):
        return None

    drive = candidate[0].lower()
    tail = candidate[2:].replace("\\", "/")
    tail = tail.lstrip("/")
    if not tail:
        return f"/mnt/{drive}"
    return f"/mnt/{drive}/{tail}"


def _wsl_to_windows_path(path: str) -> Optional[str]:
    candidate = str(path).strip().replace("\\", "/")
    if not _looks_like_wsl_mount_path(candidate):
        return None

    drive = candidate[5].upper()
    tail = candidate[7:] if len(candidate) > 7 else ""
    if not tail:
        return f"{drive}:\\"
    fixed_tail = tail.replace("/", "\\")
    return f"{drive}:\\{fixed_tail}"


def _local_fs_path(path: Optional[str]) -> Optional[str]:
    if path is None:
        return None

    candidate = str(path).strip()
    if not candidate or not is_wsl_path_bridge_enabled():
        return candidate

    if os.name == "nt":
        return _wsl_to_windows_path(candidate) or candidate

    return _windows_to_wsl_path(candidate) or candidate


def _host_launch_path(path: Optional[str]) -> Optional[str]:
    if path is None:
        return None

    candidate = str(path).strip()
    if not candidate or not is_wsl_path_bridge_enabled():
        return candidate

    return _wsl_to_windows_path(candidate) or candidate


def _is_host_windows_path(path: Optional[str]) -> bool:
    candidate = _host_launch_path(path)
    return bool(candidate and _looks_like_windows_drive_path(candidate))


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
        if port in registered_ports
        or (now - reserved_at) >= _PORT_RESERVATION_TTL_SECONDS
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


def _normalize_bundle_dir(candidate: Optional[str]) -> Optional[str]:
    if not candidate:
        return None

    local_path = str(candidate).strip()
    if not local_path:
        return None

    local_path = os.path.abspath(local_path)

    try:
        os.makedirs(local_path, exist_ok=True)
        return local_path
    except OSError:
        return None


def _timestamp_dir_name(now: Optional[float] = None) -> str:
    ts = time.time() if now is None else now
    whole = int(ts)
    frac = int((ts - whole) * 1_000_000)
    return f"{_LAUNCH_BUNDLE_ROOT}_{time.strftime('%Y%m%d-%H%M%S', time.localtime(whole))}-{frac:06d}"


def _launch_bundle_dir(root_dir: str) -> str:
    os.makedirs(root_dir, exist_ok=True)
    for _ in range(16):
        bundle_dir = os.path.join(root_dir, _timestamp_dir_name())
        try:
            os.makedirs(bundle_dir)
            return bundle_dir
        except FileExistsError:
            time.sleep(0.001)
            continue
    raise RuntimeError("Failed to allocate unique launch bundle directory")


def _is_database_path(file_path: str) -> bool:
    lower = str(file_path).lower()
    return lower.endswith(".i64") or lower.endswith(".idb")


def _candidate_database_paths(file_path: str) -> list[str]:
    normalized_path = str(file_path)
    if _is_database_path(normalized_path):
        return [normalized_path]

    stem, _suffix = os.path.splitext(normalized_path)
    ordered = [
        f"{normalized_path}.i64",
        f"{normalized_path}.idb",
        f"{stem}.i64",
        f"{stem}.idb",
    ]
    unique: list[str] = []
    seen: set[str] = set()
    for candidate in ordered:
        key = os.path.normcase(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _find_companion_database(file_path: str) -> Optional[str]:
    for candidate in _candidate_database_paths(file_path):
        if os.path.isfile(candidate):
            return candidate
    return None


def _find_companion_input_file(file_path: str) -> Optional[str]:
    normalized_path = str(file_path)
    if not _is_database_path(normalized_path):
        return normalized_path

    base_path, _database_ext = os.path.splitext(normalized_path)
    if os.path.isfile(base_path):
        return base_path
    return None


def _resolve_launch_inputs(file_path: str) -> tuple[str, Optional[str], Optional[str]]:
    normalized_path = str(file_path)
    if _is_database_path(normalized_path):
        database_path = normalized_path
        input_file_path = _find_companion_input_file(normalized_path)
        return database_path, input_file_path, database_path

    input_file_path = normalized_path
    database_path = _find_companion_database(normalized_path)
    launch_target = database_path or input_file_path
    return launch_target, input_file_path, database_path


def _stage_file(path: Optional[str], bundle_dir: str) -> Optional[str]:
    if not path:
        return None

    source_path = str(path)
    staged_local_path = os.path.join(bundle_dir, os.path.basename(source_path))
    shutil.copy2(source_path, staged_local_path)
    return staged_local_path


def _stage_target_file_for_launch(
    file_path: str, bundle_dir: str
) -> tuple[str, Optional[str]]:
    launch_target, input_file_path, database_path = _resolve_launch_inputs(file_path)
    staged_input = _stage_file(input_file_path, bundle_dir)
    staged_database = _stage_file(database_path, bundle_dir)

    launch_path = (
        staged_database
        if database_path and launch_target == database_path
        else staged_input
    )
    if not launch_path:
        raise RuntimeError(f"Failed to stage launch target for: {file_path}")

    requested_file = str(file_path)
    if input_file_path and os.path.normcase(requested_file) == os.path.normcase(
        input_file_path
    ):
        staged_requested = staged_input
    elif database_path and os.path.normcase(requested_file) == os.path.normcase(
        database_path
    ):
        staged_requested = staged_database
    else:
        staged_requested = launch_path

    return launch_path, staged_requested


def _use_direct_target_file(file_path: str) -> tuple[str, None]:
    launch_target, _input_file_path, _database_path = _resolve_launch_inputs(file_path)
    return launch_target, None


def open_in_ida(
    file_path: str,
    extra_args: Optional[List[str]] = None,
) -> dict:
    """Launch IDA and request plugin auto-start."""
    reserved_port: Optional[int] = None
    try:
        target_ida = get_ida_path()
        if not target_ida:
            return {
                "error": "IDA path not configured. Please set 'ida_path' in config.conf."
            }
        local_target_ida = _local_fs_path(target_ida)
        if not local_target_ida or not os.path.exists(local_target_ida):
            return {"error": f"IDA executable not found at: {target_ida}"}

        local_file_path = _local_fs_path(file_path)
        if not local_file_path or not os.path.exists(local_file_path):
            return {"error": f"File not found: {file_path}"}

        reserved_port = _reserve_launch_port()
        configured_bundle_dir = _normalize_bundle_dir(
            _local_fs_path(get_open_in_ida_bundle_dir())
        )
        bundle_dir = (
            _launch_bundle_dir(configured_bundle_dir) if configured_bundle_dir else None
        )
        cmd = [local_target_ida]
        launch_args = [
            arg.strip()
            for arg in (extra_args or [])
            if isinstance(arg, str) and arg.strip() and arg.strip() != "-A"
        ]
        if is_open_in_ida_autonomous_enabled():
            launch_args.insert(0, "-A")
        if configured_bundle_dir:
            assert bundle_dir is not None
            final_file_path, staged_file = _stage_target_file_for_launch(
                local_file_path, bundle_dir
            )
        else:
            final_file_path, staged_file = _use_direct_target_file(local_file_path)
        launch_file_path = _host_launch_path(final_file_path)
        reported_bundle_dir = _host_launch_path(bundle_dir)
        reported_staged_file = _host_launch_path(staged_file)
        if is_wsl_path_bridge_enabled() and not _is_host_windows_path(launch_file_path):
            return {
                "error": (
                    "WSL path bridge is enabled, but the launch target cannot be translated to a Windows path. "
                    "Configure 'open_in_ida_bundle_dir' on a Windows drive or pass a Windows-accessible file path."
                )
            }
        if launch_args:
            cmd.extend(launch_args)
        cmd.append(launch_file_path)

        env = os.environ.copy()
        env["IDA_MCP_PORT"] = str(reserved_port)
        env["IDA_MCP_AUTO_START"] = "1"
        # Pass the ida-python site-packages directory via a private env var.
        # The IDA-MCP plugin inside IDA reads this and calls
        # site.addsitedir() to make third-party packages importable.
        # Using IDAMCP_PYTHONPATH instead of PYTHONPATH to avoid interfering
        # with IDA's own Python initialization.
        ida_python_bin = get_ida_python()
        if ida_python_bin:
            _ida_python_dir = os.path.dirname(ida_python_bin)
            _site_dir = os.path.join(_ida_python_dir, "Lib", "site-packages")
            if os.path.isdir(_site_dir):
                env["IDAMCP_PYTHONPATH"] = _site_dir
        cwd = os.path.dirname(local_target_ida) or None
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=env,
                close_fds=True if sys.platform != "win32" else False,
            )
        except Exception:
            _release_launch_port(reserved_port)
            raise
        try:
            registry.register_pending_instance(
                proc.pid,
                reserved_port,
                local_file_path,
                _find_companion_database(local_file_path),
                lifecycle_state="starting",
            )
        except Exception:
            pass
        return {
            "status": "ok",
            "message": f"Launched IDA with preferred MCP port {reserved_port}: {' '.join(cmd)}",
            "requested_port": reserved_port,
            "pid": getattr(proc, "pid", None),
            "launch_bundle": reported_bundle_dir,
            "staged_file": reported_staged_file,
            "launch_target": launch_file_path,
        }
    except Exception as e:
        _release_launch_port(reserved_port)
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
