"""Database lifecycle management for the standalone MCP server.

Implements the official ida-mcp style model on top of the local bridge:

- ``open_database(path)``: attach to a GUI instance that already has the
  file open, or spawn a headless idalib worker (creating and analyzing the
  .i64 for raw binaries) — or explicitly launch a GUI instance.
- ``list_databases()`` / ``save_database()`` / ``close_database()``:
  multi-instance bookkeeping through the shared JSON registry.

"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import bridge_client, instances
from .bridge_server import BRIDGE_PORT_BASE
from .config import (
    get_ida_path,
    get_ida_python,
    get_idalib_python,
    get_request_timeout,
)

OPEN_TIMEOUT_SECONDS = 300
_ATTACH_POLL_INTERVAL = 0.5
_PORT_SCAN_LIMIT = 256

_MANAGED_LOCK = threading.Lock()
_MANAGED: Dict[int, Dict[str, Any]] = {}  # pid -> {"instance_id": ..., "spawned_at": ...}


# ============================================================================
# Launch target resolution (companion .i64 preference)
# ============================================================================


def _is_database_path(file_path: str) -> bool:
    lower = str(file_path).lower()
    return lower.endswith(".i64") or lower.endswith(".idb")


def _candidate_database_paths(file_path: str) -> List[str]:
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
    unique: List[str] = []
    seen: set[str] = set()
    for candidate in ordered:
        key = os.path.normcase(candidate)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def find_companion_database(file_path: str) -> Optional[str]:
    for candidate in _candidate_database_paths(file_path):
        if os.path.isfile(candidate):
            return candidate
    return None


def _resolve_launch_inputs(file_path: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Return (launch_target, input_file, database_path)."""
    normalized_path = str(file_path)
    if _is_database_path(normalized_path):
        base_path, _ = os.path.splitext(normalized_path)
        input_file = base_path if os.path.isfile(base_path) else None
        return normalized_path, input_file, normalized_path
    database_path = find_companion_database(normalized_path)
    return (database_path or normalized_path, normalized_path, database_path)


# ============================================================================
# Bridge port reservation for spawned instances
# ============================================================================


def _is_port_bindable(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def reserve_instance_port() -> int:
    """Pick a free bridge port for a soon-to-spawn instance."""
    start_port = BRIDGE_PORT_BASE
    used = {
        int(entry.get("port"))
        for entry in instances.read_instances()
        if isinstance(entry.get("port"), int)
    }
    for offset in range(_PORT_SCAN_LIMIT):
        candidate = start_port + offset
        if candidate in used or not _is_port_bindable(candidate):
            continue
        return candidate
    raise RuntimeError(
        f"No free instance port between {start_port} and {start_port + _PORT_SCAN_LIMIT - 1}"
    )


# ============================================================================
# idalib python resolution (headless workers)
# ============================================================================

_IDALIB_PROBE_CACHE: Dict[str, bool] = {}


def _python_can_idalib(python_path: str) -> bool:
    key = os.path.abspath(python_path)
    if key in _IDALIB_PROBE_CACHE:
        return _IDALIB_PROBE_CACHE[key]
    try:
        completed = subprocess.run(
            [python_path, "-c", "import idapro"],
            capture_output=True,
            timeout=20,
        )
        ok = completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    _IDALIB_PROBE_CACHE[key] = ok
    return ok


def _ida_install_dir() -> Optional[str]:
    """Read the IDA install dir from the user's ida-config.json."""
    import json

    for candidate in (
        os.environ.get("IDA_MCP_IDA_INSTALL_DIR"),
        os.path.join(
            str(Path(os.environ.get("APPDATA", "")) if os.name == "nt" else Path.home()),
            *(("Hex-Rays", "IDA Pro") if os.name == "nt" else (".idapro",)),
            "ida-config.json",
        ),
    ):
        if not candidate:
            continue
        try:
            document = json.loads(Path(candidate).read_text(encoding="utf-8"))
            install_dir = ((document.get("Paths") or {}).get("ida-install-dir") or "").strip()
            if install_dir and os.path.isdir(install_dir):
                return install_dir
        except (OSError, ValueError):
            continue
    return None


def _install_dir_python_candidates(install_dir: str) -> List[str]:
    """Python executables that ship beside an IDA installation."""
    ida_python_dir = os.path.join(install_dir, "ida-python")
    candidates: List[str] = []
    if os.path.isdir(ida_python_dir):
        bin_dir = os.path.join(ida_python_dir, "bin")
        for name in ("python3", "python"):
            candidates.append(os.path.join(bin_dir, name))
        # versioned binaries (e.g. python3.12) and Windows layouts
        if os.path.isdir(bin_dir):
            for entry in sorted(os.listdir(bin_dir)):
                if re.match(r"^python3\.\d+$", entry):
                    candidates.append(os.path.join(bin_dir, entry))
        for name in ("python.exe", "pythonw.exe"):
            candidates.append(os.path.join(ida_python_dir, name))
    return candidates


def resolve_idalib_python(persist: bool = True) -> Optional[str]:
    """Find a Python interpreter with the official idalib bindings active.

    Probes, in order: configured idalib_python, configured/detected
    ida_python, the IDA installation's own ida-python runtime (discovered
    from ida-config.json), a managed activation venv, and the legacy
    ~/.idapro/venv. Successful late detections are cached into the
    user-scope config so later launches skip probing.
    """
    candidates: List[str] = []
    configured = get_idalib_python()
    if configured:
        candidates.append(configured)
    ida_python = get_ida_python()
    if ida_python:
        candidates.append(ida_python)
    install_dir = _ida_install_dir()
    if install_dir:
        candidates.extend(_install_dir_python_candidates(install_dir))
    state_venv = instances.get_state_dir() / "idalib-venv"
    for suffix in ("bin/python", "bin/python3", "Scripts/python.exe"):
        candidates.append(str(state_venv / suffix))
    legacy_venv = Path.home() / ".idapro" / "venv"
    for suffix in ("bin/python", "Scripts/python.exe"):
        candidates.append(str(legacy_venv / suffix))

    seen: set[str] = set()
    for candidate in candidates:
        normalized = os.path.normcase(os.path.abspath(candidate))
        if normalized in seen or not os.path.isfile(candidate):
            continue
        seen.add(normalized)
        if _python_can_idalib(candidate):
            if persist and candidate not in (configured, ida_python):
                from .config import persist_user_setting

                persist_user_setting("idalib_python", os.path.abspath(candidate))
            return candidate
    return None


def _package_parent_dir() -> str:
    return str(Path(__file__).resolve().parents[1])


# ============================================================================
# Launch / attach / close
# ============================================================================


def _wait_for_instance(
    pid: Optional[int],
    match_path: Optional[str],
    timeout: float,
) -> Optional[Dict[str, Any]]:
    """Poll the registry until the spawned instance registers and answers."""
    deadline = time.monotonic() + max(float(timeout), 5.0)
    while time.monotonic() < deadline:
        for entry in instances.read_instances():
            if pid is not None and entry.get("pid") != pid:
                continue
            if match_path is not None:
                found = instances.find_by_path(match_path)
                if found is None or found.get("instance_id") != entry.get("instance_id"):
                    continue
            if bridge_client.is_alive(entry):
                return entry
        time.sleep(_ATTACH_POLL_INTERVAL)
    return None


def launch_headless(target_path: str, *, timeout: float = OPEN_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """Spawn an idalib worker; it creates/analyzes the .i64 and self-registers."""
    idalib_python = resolve_idalib_python()
    if not idalib_python:
        return {
            "error": (
                "No Python with idalib activated was found. Install the idapro "
                "wheel from <IDA>/idalib/python into your IDA Python (or run "
                "`python py-activate-idalib.py` from the IDA install dir), or "
                "set 'idalib_python' in config.conf."
            )
        }

    port = reserve_instance_port()
    env = os.environ.copy()
    env["IDA_MCP_PORT"] = str(port)
    package_parent = _package_parent_dir()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{package_parent}{os.pathsep}{existing}" if existing else package_parent
    )
    log_path = instances.get_state_dir() / f"worker-{os.getpid()}-{int(time.time())}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        log_handle = open(log_path, "w", encoding="utf-8", errors="replace")
        proc = subprocess.Popen(
            [
                idalib_python,
                "-m",
                "ida_mcp.worker",
                target_path,
                "--port",
                str(port),
            ],
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        return {"error": f"Failed to launch idalib worker: {exc}"}
    finally:
        try:
            log_handle.close()
        except Exception:  # noqa: BLE001 - child keeps its own fd
            pass

    entry = _wait_for_instance(proc.pid, None, timeout)
    if entry is None:
        proc.terminate()
        return {"error": "idalib worker did not become available in time", "pid": proc.pid}
    with _MANAGED_LOCK:
        _MANAGED[proc.pid] = {
            "instance_id": entry.get("instance_id"),
            "headless": True,
            "spawned_at": time.time(),
            "process": proc,
        }
    return {"status": "ok", "mode": "headless", "instance": entry}


def launch_gui(
    file_path: str,
    *,
    extra_args: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Launch an IDA GUI process with the plugin auto-starting the bridge."""
    target_ida = get_ida_path()
    if not target_ida:
        return {"error": "IDA path not configured. Set 'ida_path' in config.conf."}
    local_target_ida = target_ida
    if not local_target_ida or not os.path.exists(local_target_ida):
        return {"error": f"IDA executable not found at: {target_ida}"}

    local_file_path = file_path
    if not local_file_path or not os.path.exists(local_file_path):
        return {"error": f"File not found: {file_path}"}

    port = reserve_instance_port()
    final_file_path, _input, _db = _resolve_launch_inputs(local_file_path)

    cmd = [local_target_ida]
    launch_args = [
        arg.strip()
        for arg in (extra_args or [])
        if isinstance(arg, str) and arg.strip() and arg.strip() != "-A"
    ]
    # Programmatic GUI launches are always autonomous (no dialogs).
    launch_args.insert(0, "-A")
    cmd.extend(launch_args)
    cmd.append(final_file_path)

    env = os.environ.copy()
    env["IDA_MCP_PORT"] = str(port)
    cwd = os.path.dirname(local_target_ida) or None
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env, close_fds=(sys.platform != "win32")
        )
    except OSError as exc:
        return {"error": f"Failed to launch IDA: {exc}"}

    entry = _wait_for_instance(proc.pid, None, OPEN_TIMEOUT_SECONDS)
    if entry is None:
        return {
            "status": "launched",
            "message": "IDA launched but the instance did not register in time; "
            "it may still appear via list_databases().",
            "pid": proc.pid,
        }
    with _MANAGED_LOCK:
        _MANAGED[proc.pid] = {
            "instance_id": entry.get("instance_id"),
            "headless": False,
            "spawned_at": time.time(),
            "process": proc,
        }
    return {"status": "ok", "mode": "gui", "instance": entry}


def open_database(
    path: str,
    *,
    set_current: bool = True,
    headless: str = "auto",
    wait_for_analysis: bool = True,
    timeout: float = OPEN_TIMEOUT_SECONDS,
    extra_args: Optional[List[str]] = None,
    select_callback=None,
) -> Dict[str, Any]:
    """Attach to a live instance for ``path`` or launch a new one.

    headless: "auto" (attach → headless worker), "true"/"headless" (force
    idalib worker), "false"/"gui" (launch the IDA GUI).
    """
    local_path = str(path).strip()
    if not local_path or not os.path.exists(local_path):
        return {"error": f"File not found: {path}"}
    local_path = os.path.abspath(local_path)

    # 1. Attach to a live instance that already has this file/database open.
    existing = instances.find_by_path(local_path)
    if existing is not None and bridge_client.is_alive(existing):
        result = {
            "status": "ok",
            "mode": "attached",
            "instance": existing,
        }
    else:
        mode = headless.strip().lower()
        want_gui = mode in {"false", "no", "gui", "graphical"}
        if want_gui:
            result = launch_gui(local_path, extra_args=extra_args)
        else:
            launch_target, _input, _db = _resolve_launch_inputs(local_path)
            result = launch_headless(launch_target, timeout=timeout)
        if "error" in result:
            return result

    entry = result.get("instance")
    if entry and set_current and select_callback:
        select_callback(entry.get("instance_id"))

    if entry and wait_for_analysis:
        try:
            bridge_client.call_tool(
                entry,
                "wait_for_analysis",
                {},
                timeout=max(float(timeout), 30.0),
            )
        except Exception:  # noqa: BLE001 - analysis wait is best effort
            pass

    if entry:
        result["instance"] = dict(entry)
    return result


def save_database(instance_entry: Dict[str, Any]) -> Dict[str, Any]:
    return bridge_client.call_tool(
        instance_entry, "save_idb", {"path": ""}, timeout=get_request_timeout()
    )


def close_database(
    instance_entry: Dict[str, Any],
    *,
    terminate: bool = False,
    save: bool = True,
) -> Dict[str, Any]:
    """Detach from an instance; terminate managed/headless ones by default.

    GUI instances stay open unless terminate=true, mirroring the official
    "databases open in the IDA GUI stay open" semantics.
    """
    instance_id = instance_entry.get("instance_id")
    pid = instance_entry.get("pid")
    with _MANAGED_LOCK:
        managed = _MANAGED.get(pid)
    headless = bool(instance_entry.get("headless"))

    should_terminate = terminate or headless or bool(managed and managed.get("headless"))
    if not should_terminate:
        return {
            "status": "detached",
            "instance_id": instance_id,
            "message": "Instance left running; call again with terminate=true to close IDA.",
        }

    try:
        bridge_client.request_shutdown(instance_entry, save=save)
    except Exception as exc:  # noqa: BLE001 - force-kill below when possible
        process = (managed or {}).get("process")
        if process is not None:
            try:
                process.terminate()
            except OSError:
                pass
        return {"status": "error", "error": f"shutdown request failed: {exc}"}

    process = (managed or {}).get("process")
    if process is not None:
        try:
            process.wait(timeout=15)
        except (subprocess.TimeoutExpired, OSError):
            try:
                process.kill()
            except OSError:
                pass
    with _MANAGED_LOCK:
        _MANAGED.pop(pid, None)
    instances.remove_instance(str(instance_id))
    return {"status": "closed", "instance_id": instance_id, "saved": save}


def shutdown_managed() -> None:
    """Terminate every worker this process spawned (server shutdown path)."""
    with _MANAGED_LOCK:
        managed = list(_MANAGED.items())
    for pid, info in managed:
        process = info.get("process")
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
        except OSError:
            pass
        with _MANAGED_LOCK:
            _MANAGED.pop(pid, None)
