"""Database lifecycle management for the standalone MCP server.

Implements multi-database lifecycle management on top of the local bridge:

- ``open_database(path)``: attach to a live worker that already has the file
  open (or is still loading it), or spawn a headless idalib worker (creating
  and analyzing the .i64 for raw binaries).
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
    get_ida_python,
    get_request_timeout,
)

OPEN_TIMEOUT_SECONDS = 300
_ATTACH_POLL_INTERVAL = 0.5
_PORT_SCAN_LIMIT = 256

_MANAGED_LOCK = threading.Lock()
_MANAGED: Dict[str, Dict[str, Any]] = {}  # instance_id -> {"instance_id": ..., "spawned_at": ...}


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
    """Find the Python interpreter for headless idalib workers.

    Normally this is simply ida_python (one runtime for both roles). Probes,
    in order: configured/detected ida_python, the IDA installation's own
    ida-python runtime (discovered from ida-config.json), a managed
    activation venv, and the legacy ~/.idapro/venv. A successful late
    detection is cached as ida_python in the user-scope config.
    """
    candidates: List[str] = []
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
            if persist and candidate != ida_python:
                from .config import persist_user_setting

                # One runtime for both roles: cache it as ida_python.
                persist_user_setting("ida_python", os.path.abspath(candidate))
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
    port: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Poll the registry until the spawned instance registers and answers.

    The registering pid is not always the launched pid: on Windows a venv
    ``Scripts\\python.exe`` is a redirector whose child (the real
    interpreter) self-registers, so pid matching never succeeds there.
    Match by the reserved bridge port first — headless workers bind exactly
    the port passed via ``IDA_MCP_PORT`` — and accept a pid match otherwise.
    """
    deadline = time.monotonic() + max(float(timeout), 5.0)
    while time.monotonic() < deadline:
        for entry in instances.read_instances():
            pid_match = pid is not None and entry.get("pid") == pid
            port_match = port is not None and entry.get("port") == port
            if not pid_match and not port_match:
                continue
            if match_path is not None:
                found = instances.find_by_path(match_path)
                if found is None or found.get("instance_id") != entry.get("instance_id"):
                    continue
            if bridge_client.is_alive(entry):
                return entry
        time.sleep(_ATTACH_POLL_INTERVAL)
    return None


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    """Terminate a spawned worker and everything it spawned.

    Needed on Windows where a venv redirector python makes the real worker
    a grandchild: TerminateProcess on the redirector would orphan it.
    """
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                timeout=10,
                check=False,
            )
        else:
            proc.terminate()
    except (OSError, subprocess.SubprocessError):
        try:
            proc.terminate()
        except OSError:
            pass


def launch_headless(target_path: str, *, timeout: float = OPEN_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """Spawn an idalib worker; it creates/analyzes the .i64 and self-registers."""
    idalib_python = resolve_idalib_python()
    if idalib_python:
        # Surface which interpreter drives headless workers (stderr keeps
        # stdio MCP transport clean).
        print(f"[IDA-MCP] headless worker python: {idalib_python}", file=sys.stderr)
    if not idalib_python:
        return {
            "error": (
                "IDA's Python cannot 'import idapro' yet. Install the idalib "
                "bindings into it (pip install <IDA>/idalib/python/idapro-*.whl "
                f"&& python <IDA>/py-activate-idalib.py, using the interpreter "
                "configured as 'ida_python'), then retry."
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
        old_logs = sorted(
            log_path.parent.glob("worker-*.log"), key=lambda pth: pth.stat().st_mtime
        )
        for stale in old_logs[:-10]:
            stale.unlink(missing_ok=True)
    except OSError:
        pass
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

    entry = _wait_for_instance(proc.pid, None, timeout, port=port)
    if entry is None:
        _terminate_process_tree(proc)
        return {"error": "idalib worker did not become available in time", "pid": proc.pid}
    instance_id = str(entry.get("instance_id"))
    with _MANAGED_LOCK:
        _MANAGED[instance_id] = {
            "instance_id": instance_id,
            "headless": True,
            "spawned_at": time.time(),
            "process": proc,
        }
    return {
        "status": "ok",
        "mode": "headless",
        "instance": entry,
        "worker_python": idalib_python,
    }


def open_database(
    path: str,
    *,
    wait_for_analysis: bool = True,
    timeout: float = OPEN_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Attach to a live worker for ``path`` or spawn a new idalib worker.

    Returns the instance record; callers route per call via instance_id
    (there is no server-side default selection).
    """
    local_path = str(path).strip()
    if not local_path or not os.path.exists(local_path):
        return {"error": f"File not found: {path}"}
    local_path = os.path.abspath(local_path)

    # 1. Attach to a live instance that already has this file/database open
    #    (or is still loading it — such entries carry only "target").
    existing = instances.find_by_path(local_path)
    if existing is None:
        existing = next(
            (
                entry
                for entry in instances.list_live_instances()
                if str(entry.get("target") or "") == local_path
            ),
            None,
        )
    if existing is not None and bridge_client.is_alive(existing):
        result = {
            "status": "ok",
            "mode": "attached",
            "instance": existing,
        }
    else:
        launch_target, _input, _db = _resolve_launch_inputs(local_path)
        result = launch_headless(launch_target, timeout=timeout)
        if "error" in result:
            return result

    entry = result.get("instance")

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
        # Refresh the entry: the registry record written at attach time
        # still carries the loading-era (empty) paths.
        refreshed = instances.find_by_id(str(entry.get("instance_id")))
        result["instance"] = dict(refreshed or entry)
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
    """Release an idalib worker; the last active user shuts it down.

    ``terminate=true`` forces shutdown even while other users hold leases.
    """
    instance_id = instance_entry.get("instance_id")
    managed_key = str(instance_id) if instance_id is not None else None
    with _MANAGED_LOCK:
        managed = _MANAGED.get(managed_key) if managed_key else None
    headless = bool(instance_entry.get("headless"))

    # Release our lease first; only the last active user (or terminate=true)
    # may shut a shared headless worker down.
    holders: List[int] = []
    if instance_id is not None:
        try:
            instances.lease_remove(str(instance_id), os.getpid())
        except Exception:  # noqa: BLE001 - leases are best effort
            pass
        try:
            holders = instances.lease_holders(str(instance_id))
        except Exception:  # noqa: BLE001
            holders = []

    should_terminate = terminate or bool((managed or {}).get("headless")) or not holders
    if not should_terminate:
        return {
            "status": "released",
            "instance_id": instance_id,
            "remaining_users": len(holders),
            "message": "Other agents are still using this instance; it stays "
                       "running. Call again with terminate=true to force-close.",
        }

    try:
        bridge_client.request_shutdown(instance_entry, save=save)
    except Exception as exc:  # noqa: BLE001 - force-kill below when possible
        process = (managed or {}).get("process")
        if process is not None:
            _terminate_process_tree(process)
        return {"status": "error", "error": f"shutdown request failed: {exc}"}

    process = (managed or {}).get("process")
    if process is not None:
        try:
            process.wait(timeout=15)
        except (subprocess.TimeoutExpired, OSError):
            _terminate_process_tree(process)
    with _MANAGED_LOCK:
        if managed_key:
            _MANAGED.pop(managed_key, None)
    instances.remove_instance(str(instance_id))
    return {"status": "closed", "instance_id": instance_id, "saved": save}


def shutdown_managed() -> None:
    """Terminate every worker this process spawned (server shutdown path)."""
    with _MANAGED_LOCK:
        managed = list(_MANAGED.items())
    for managed_key, info in managed:
        process = info.get("process")
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    _terminate_process_tree(process)
        except OSError:
            pass
        with _MANAGED_LOCK:
            _MANAGED.pop(managed_key, None)
