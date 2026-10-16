"""Shared JSON instance registry for IDA-MCP.

Every IDA process running IDA-MCP (GUI plugin or idalib worker) publishes one
entry in ``<state_dir>/instances.json``. The standalone MCP server reads the
same file to discover instances, attach to GUI databases, and track the
headless workers it spawned.

The registry is intentionally file-based and lock-guarded: no daemon, no port
reservation protocol, no forwarding hop. Readers prune entries whose owning
process is gone, so a crashed IDA disappears from the list automatically.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_REGISTRY_VERSION = 1
_DEFAULT_STATE_DIRNAME = "ida-mcp"


def get_state_dir() -> Path:
    """Directory holding the instance registry and other IDA-MCP state."""
    override = os.environ.get("IDA_MCP_STATE_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    idausr = os.environ.get("IDAUSR", "").strip()
    if idausr:
        first = idausr.split(os.pathsep)[0].strip()
        if first:
            return Path(first).expanduser() / _DEFAULT_STATE_DIRNAME
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "").strip()
        if appdata:
            return Path(appdata) / "Hex-Rays" / "IDA Pro" / _DEFAULT_STATE_DIRNAME
    return Path.home() / ".idapro" / _DEFAULT_STATE_DIRNAME


def get_instances_path() -> Path:
    return get_state_dir() / "instances.json"


def new_instance_id() -> str:
    return "i-" + secrets.token_hex(4)


# ============================================================================
# Cross-platform PID liveness
# ============================================================================


def pid_alive(pid: int) -> bool:
    """Return True when ``pid`` refers to a running process."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == STILL_ACTIVE
                return True
            finally:
                kernel32.CloseHandle(handle)
        else:
            os.kill(pid, 0)
            return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Owned by another user but still running.
        return True
    except OSError:
        return False


# ============================================================================
# File locking (best effort, cross platform)
# ============================================================================


class _FileLock:
    """Advisory lock file guarding registry mutations."""

    def __init__(self, path: Path):
        self._path = path
        self._handle = None

    def __enter__(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self._path, "a+")
        try:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        except ImportError:  # pragma: no cover - Windows
            try:
                import msvcrt

                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_LOCK, 1)
            except (ImportError, OSError):
                pass
        except OSError:
            pass
        return self

    def __exit__(self, *exc_info):
        if self._handle is None:
            return False
        try:
            try:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
        finally:
            self._handle.close()
            self._handle = None
        return False


def _lock_path() -> Path:
    return get_state_dir() / "instances.lock"


# ============================================================================
# Registry read / write
# ============================================================================


def _normalize_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    if not isinstance(entry.get("port"), int) or not isinstance(
        entry.get("pid"), int
    ):
        return None
    entry.setdefault("instance_id", f"pid-{entry['pid']}")
    entry.setdefault("host", "127.0.0.1")
    entry.setdefault("input_file", "")
    entry.setdefault("database_path", "")
    entry.setdefault("headless", False)
    entry.setdefault("started_at", 0.0)
    entry["last_seen_at"] = float(entry.get("last_seen_at") or time.time())
    return entry


def read_instances() -> List[Dict[str, Any]]:
    """Read the registry, pruning entries whose process is gone."""
    path = get_instances_path()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []

    raw_entries = document.get("instances", []) if isinstance(document, dict) else []
    entries: List[Dict[str, Any]] = []
    pruned = False
    for raw in raw_entries:
        entry = _normalize_entry(raw)
        if entry is None:
            pruned = True
            continue
        if not pid_alive(entry["pid"]):
            pruned = True
            continue
        entries.append(entry)

    if pruned:
        write_instances(entries)
    return entries


def write_instances(entries: List[Dict[str, Any]]) -> None:
    """Atomically replace the registry content."""
    path = get_instances_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"version": _REGISTRY_VERSION, "instances": entries}
    with _FileLock(_lock_path()):
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=".instances-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2)
            os.replace(tmp_name, path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise


def _mutate(action) -> List[Dict[str, Any]]:
    """Apply ``action(entries)`` under the registry lock and persist."""
    with _FileLock(_lock_path()):
        path = get_instances_path()
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            entries = [
                e
                for e in (document.get("instances", []) if isinstance(document, dict) else [])
                if isinstance(e, dict) and pid_alive(int(e.get("pid") or 0))
            ]
        except (OSError, ValueError):
            entries = []
        action(entries)
        document = {"version": _REGISTRY_VERSION, "instances": entries}
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=".instances-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2)
            os.replace(tmp_name, path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        return entries


def add_instance(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Insert or refresh this process's registry entry."""
    normalized = _normalize_entry(dict(entry))
    if normalized is None:
        raise ValueError("instance entry requires integer pid and port")

    def action(entries: List[Dict[str, Any]]) -> None:
        entries[:] = [
            e
            for e in entries
            if e.get("instance_id") != normalized["instance_id"]
            and e.get("pid") != normalized["pid"]
        ]
        entries.append(normalized)

    _mutate(action)
    return normalized


def touch_instance(instance_id: str) -> None:
    """Refresh last_seen_at for one entry (cheap keep-alive marker)."""

    def action(entries: List[Dict[str, Any]]) -> None:
        now = time.time()
        for e in entries:
            if e.get("instance_id") == instance_id:
                e["last_seen_at"] = now

    _mutate(action)


def remove_instance(instance_id: str) -> None:
    def action(entries: List[Dict[str, Any]]) -> None:
        entries[:] = [e for e in entries if e.get("instance_id") != instance_id]

    _mutate(action)


# ============================================================================
# Cross-process usage leases (who is currently using an instance)
# ============================================================================


def _leases_path() -> Path:
    return get_state_dir() / "leases.json"


def _read_leases() -> Dict[str, List[int]]:
    try:
        document = json.loads(_leases_path().read_text(encoding="utf-8"))
        leases = document.get("leases", {})
        return {k: v for k, v in leases.items() if isinstance(v, list)} if isinstance(leases, dict) else {}
    except (OSError, ValueError):
        return {}


def _prune_lease_pids(pids: List[int]) -> List[int]:
    return [pid for pid in pids if pid_alive(int(pid))]


def _write_leases(leases: Dict[str, List[int]]) -> None:
    """Write the full lease map; caller must hold the registry lock
    (mutations read-modify-write under the same flock, so no merge)."""
    path = _leases_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"version": _REGISTRY_VERSION, "leases": leases}
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".leases-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
        os.replace(tmp_name, path)
    except OSError:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def lease_add(instance_id: str, pid: int) -> None:
    """Record that ``pid`` is actively using ``instance_id``."""
    with _FileLock(_lock_path()):
        leases = _read_leases()
        pids = _prune_lease_pids(leases.get(instance_id, []))
        if pid not in pids:
            pids.append(pid)
        leases[instance_id] = pids
        _write_leases(leases)


def lease_remove(instance_id: str, pid: int) -> None:
    with _FileLock(_lock_path()):
        leases = _read_leases()
        pids = [p for p in _prune_lease_pids(leases.get(instance_id, [])) if p != pid]
        if pids:
            leases[instance_id] = pids
        else:
            leases.pop(instance_id, None)
        _write_leases(leases)


def lease_holders(instance_id: str) -> List[int]:
    """Live pids (excluding none) currently using the instance."""
    return _prune_lease_pids(_read_leases().get(instance_id, []))


# ============================================================================
# Lookup helpers
# ============================================================================


def _same_path(left: str, right: str) -> bool:
    if not left or not right:
        return False
    try:
        return os.path.samefile(left, right)
    except OSError:
        return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
            os.path.abspath(right)
        )


def find_by_id(instance_id: str) -> Optional[Dict[str, Any]]:
    for entry in read_instances():
        if entry.get("instance_id") == instance_id:
            return entry
    return None


def find_by_pid(pid: int) -> Optional[Dict[str, Any]]:
    for entry in read_instances():
        if entry.get("pid") == pid:
            return entry
    return None


def find_by_path(path: str) -> Optional[Dict[str, Any]]:
    """Find a live instance whose input file or database matches ``path``."""
    for entry in read_instances():
        if _same_path(str(entry.get("input_file") or ""), path):
            return entry
        if _same_path(str(entry.get("database_path") or ""), path):
            return entry
    return None


def find_by_port(port: int) -> Optional[Dict[str, Any]]:
    for entry in read_instances():
        if entry.get("port") == port:
            return entry
    return None


def list_live_instances() -> List[Dict[str, Any]]:
    """List instances sorted oldest-first (stable selection order)."""
    return sorted(read_instances(), key=lambda e: (e.get("started_at") or 0, e.get("port") or 0))
