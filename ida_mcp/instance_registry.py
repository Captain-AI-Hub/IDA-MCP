"""Shared instance registry state and lifecycle helpers for the gateway."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from typing import Any, Dict, List, Optional

from starlette.responses import JSONResponse

from .config import (
    get_http_bind_host,
    get_http_connect_host,
    get_http_path,
    get_http_port,
)


LOCALHOST = "127.0.0.1"
GATEWAY_BIND_HOST = get_http_bind_host()
GATEWAY_CONNECT_HOST = get_http_connect_host()
GATEWAY_PORT = get_http_port()
MCP_PATH = get_http_path()

_instances: List[Dict[str, Any]] = []
_lock = threading.RLock()
_current_instance_port: Optional[int] = None
_call_locks: Dict[int, asyncio.Lock] = {}
_CALL_LOCKS_GUARD = threading.Lock()
_proxy_ready = False
_proxy_last_error: Optional[str] = None
_gateway_started_at = time.time()

INSTANCE_HEALTH_HEALTHY = "healthy"
INSTANCE_HEALTH_DEGRADED = "degraded"
INSTANCE_HEALTH_UNREACHABLE = "unreachable"
INSTANCE_HEALTH_UNRESPONSIVE = "unresponsive"
INSTANCE_HEALTH_ERROR = "error"
INSTANCE_FAILURE_QUARANTINE_SECONDS = 60.0
INSTANCE_FAILURE_THRESHOLD = 2
MAIN_THREAD_STALE_SECONDS = 30.0
PENDING_INSTANCE_TTL_SECONDS = 180.0  # Reap "starting" instances after 3 min

# TTL cache for _reap_dead_instances to avoid N TCP probes on every request.
_last_reap_ts: list[float] = [0.0]


def _debug_log(event: str, **fields: Any) -> None:  # pragma: no cover
    try:
        from .registry_routes import _debug_log as log
    except ImportError:
        from ida_mcp.registry_routes import _debug_log as log
    log(event, **fields)


def _now() -> float:
    return time.time()


def _find_instance_index_by_pid(pid: Any) -> Optional[int]:
    for idx, entry in enumerate(_instances):
        if entry.get("pid") == pid:
            return idx
    return None


def _probe_port_alive(port: int, timeout: float = 2.0) -> bool:
    """Return True if a TCP connection to localhost:port succeeds."""
    try:
        with socket.create_connection((LOCALHOST, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, OSError, socket.timeout):
        return False


def _reap_dead_instances() -> int:
    """Remove instances whose port is no longer reachable.

    Must be called while ``_lock`` is held.  Returns the number removed.

    Results are cached for ``_REAP_TTL_SECONDS`` to avoid N TCP probes
    on every request.
    """
    import time as _time

    _REAP_TTL_SECONDS = 15.0
    _SEEN_GRACE_SECONDS = 30.0  # skip TCP probe if instance was seen this recently
    now = _time.monotonic()
    if now - _last_reap_ts[0] < _REAP_TTL_SECONDS:
        return 0

    alive: List[Dict[str, Any]] = []
    dead: List[Dict[str, Any]] = []
    now_epoch = _time.time()
    for entry in _instances:
        # If the instance registered or sent a status update recently, it is
        # alive by definition — no need for a TCP probe.  This prevents the
        # gateway from evicting instances whose embedded MCP server briefly
        # cannot accept connections (e.g. IDA main thread busy).
        last_seen = entry.get("last_seen_at")
        if last_seen and (now_epoch - float(last_seen)) < _SEEN_GRACE_SECONDS:
            alive.append(entry)
            continue
        port = entry.get("port")
        if isinstance(port, int) and _probe_port_alive(port):
            alive.append(entry)
        else:
            dead.append(entry)
    if dead:
        _instances.clear()
        _instances.extend(alive)
        for d in dead:
            _debug_log(
                "REAP_DEAD",
                pid=d.get("pid"),
                port=d.get("port"),
                state=d.get("effective_state") or d.get("health"),
            )
    _last_reap_ts[0] = now
    return len(dead)


def _reap_stale_pending_instances() -> int:
    """Remove pending ("starting") instances whose TTL has expired.

    An instance is considered stale when it has been in a non-ready state
    (no successful health check) for longer than ``PENDING_INSTANCE_TTL_SECONDS``.

    Returns the number of reaped entries.  Must be called while ``_lock`` is held.
    """
    now = _now()
    deadline = now - PENDING_INSTANCE_TTL_SECONDS
    stale: List[int] = []
    for idx, entry in enumerate(_instances):
        state = str(entry.get("effective_state") or entry.get("health") or "")
        if state in {"ready", INSTANCE_HEALTH_HEALTHY}:
            continue
        started = float(entry.get("started") or entry.get("registered_at") or now)
        if started < deadline:
            stale.append(idx)
    # Remove in reverse order to keep indices valid.
    for idx in reversed(stale):
        removed = _instances.pop(idx)
        _debug_log(
            "REAP_STALE",
            pid=removed.get("pid"),
            port=removed.get("port"),
            state=removed.get("effective_state") or removed.get("health"),
        )
    return len(stale)


def _instance_sort_key(entry: Dict[str, Any]) -> tuple[int, int, float, int]:
    snapshot = _public_instance_record(entry)
    port = snapshot.get("port")
    quarantined_until = float(snapshot.get("quarantined_until") or 0.0)
    effective_state = str(snapshot.get("effective_state") or "")
    is_quarantined = quarantined_until > _now()
    health_penalty = (
        1
        if effective_state
        in {
            INSTANCE_HEALTH_UNREACHABLE,
            INSTANCE_HEALTH_UNRESPONSIVE,
            INSTANCE_HEALTH_ERROR,
            "starting",
            "analyzing",
        }
        else 0
    )
    return (
        1 if is_quarantined else 0,
        health_penalty,
        0 if port == 10000 else 1,
        float(entry.get("started", float("inf"))),
    )


def _main_thread_lag_seconds(
    entry: Dict[str, Any], now: Optional[float] = None
) -> Optional[float]:
    last_tick = entry.get("main_thread_last_tick_at")
    if last_tick is None:
        return None
    try:
        lag = float((now if now is not None else _now()) - float(last_tick))
    except (TypeError, ValueError):
        return None
    return max(lag, 0.0)


def _derive_effective_state(
    entry: Dict[str, Any], now: Optional[float] = None
) -> tuple[str, Optional[str], bool]:
    now = _now() if now is None else now
    ready = bool(entry.get("ready", True))
    lifecycle_state = str(entry.get("lifecycle_state") or "").strip() or None
    health = str(entry.get("health") or INSTANCE_HEALTH_HEALTHY)
    lag = _main_thread_lag_seconds(entry, now)
    main_thread_stale = ready and lag is not None and lag > MAIN_THREAD_STALE_SECONDS

    if not ready:
        state = lifecycle_state or "starting"
        return state, "instance_not_ready", main_thread_stale
    if main_thread_stale:
        return INSTANCE_HEALTH_UNRESPONSIVE, "main_thread_stale", True
    if health in {
        INSTANCE_HEALTH_UNREACHABLE,
        INSTANCE_HEALTH_UNRESPONSIVE,
        INSTANCE_HEALTH_ERROR,
    }:
        return health, f"health_{health}", False
    if lifecycle_state in {"starting", "analyzing"}:
        return lifecycle_state, "lifecycle", False
    return "ready", None, False


def _public_instance_record(entry: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = dict(entry)
    now = _now()
    effective_state, effective_reason, main_thread_stale = _derive_effective_state(
        entry, now
    )
    snapshot["effective_state"] = effective_state
    snapshot["effective_reason"] = effective_reason
    snapshot["main_thread_stale"] = main_thread_stale
    snapshot["main_thread_lag_seconds"] = _main_thread_lag_seconds(entry, now)
    return snapshot


def _auto_routable_instance(entry: Dict[str, Any]) -> bool:
    snapshot = _public_instance_record(entry)
    return str(snapshot.get("effective_state") or "") == "ready"


def _preflight_instance_route(entry: Dict[str, Any]) -> Optional[JSONResponse]:
    snapshot = _public_instance_record(entry)
    effective_state = str(snapshot.get("effective_state") or "")
    port = snapshot.get("port")
    if effective_state in {"starting", "analyzing"}:
        return JSONResponse(
            {
                "error": f"Instance on port {port} is not ready yet ({effective_state})",
                "effective_state": effective_state,
            },
            status_code=503,
        )
    if effective_state == INSTANCE_HEALTH_UNRESPONSIVE:
        return JSONResponse(
            {
                "error": f"Instance on port {port} is unresponsive",
                "effective_state": effective_state,
                "main_thread_stale": bool(snapshot.get("main_thread_stale")),
            },
            status_code=504,
        )
    return None


def _with_gateway_metadata(
    payload: Dict[str, Any], previous: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    now = _now()
    record = dict(payload)
    previous = previous or {}
    record.setdefault("registered_at", previous.get("registered_at", now))
    record.setdefault("health", previous.get("health", INSTANCE_HEALTH_HEALTHY))
    record.setdefault("last_success_at", previous.get("last_success_at"))
    record.setdefault("last_failure_at", previous.get("last_failure_at"))
    record.setdefault("last_error", previous.get("last_error"))
    record.setdefault("last_error_kind", previous.get("last_error_kind"))
    record.setdefault(
        "consecutive_failures", int(previous.get("consecutive_failures") or 0)
    )
    record.setdefault(
        "quarantined_until", float(previous.get("quarantined_until") or 0.0)
    )
    return record


def _mark_instance_success(port: int) -> None:
    now = _now()
    with _lock:
        for entry in _instances:
            if entry.get("port") != port:
                continue
            entry["health"] = INSTANCE_HEALTH_HEALTHY
            entry["last_success_at"] = now
            entry["last_error"] = None
            entry["last_error_kind"] = None
            entry["consecutive_failures"] = 0
            entry["quarantined_until"] = 0.0
            break


def _mark_instance_failure(
    port: int, health: str, error: str, error_kind: str, quarantine: bool = False
) -> None:
    now = _now()
    with _lock:
        for entry in _instances:
            if entry.get("port") != port:
                continue
            failures = int(entry.get("consecutive_failures") or 0) + 1
            entry["health"] = health
            entry["last_failure_at"] = now
            entry["last_error"] = error
            entry["last_error_kind"] = error_kind
            entry["consecutive_failures"] = failures
            if quarantine or failures >= INSTANCE_FAILURE_THRESHOLD:
                entry["quarantined_until"] = now + INSTANCE_FAILURE_QUARANTINE_SECONDS
            break


def _classify_call_exception(exc: Exception) -> tuple[str, int, str]:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return INSTANCE_HEALTH_UNRESPONSIVE, 504, "timeout"
    name = type(exc).__name__.lower()
    if "timeout" in name:
        return INSTANCE_HEALTH_UNRESPONSIVE, 504, "timeout"
    if isinstance(exc, OSError):
        return INSTANCE_HEALTH_UNREACHABLE, 503, "connect"
    return INSTANCE_HEALTH_ERROR, 500, "backend"


def _proxy_status() -> Dict[str, Any]:
    return {
        "enabled": True,
        "running": _proxy_ready,
        "url": f"http://{GATEWAY_CONNECT_HOST}:{GATEWAY_PORT}{MCP_PATH}",
        "host": GATEWAY_CONNECT_HOST,
        "bind_host": GATEWAY_BIND_HOST,
        "port": GATEWAY_PORT,
        "path": MCP_PATH,
        "last_error": None
        if _proxy_ready
        else (_proxy_last_error or "gateway MCP route not ready"),
    }
