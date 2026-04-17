"""Standalone single-port gateway for instance registration, routing, and MCP proxying."""

from __future__ import annotations

import asyncio
import json
import pathlib
import socket
import sys
import threading
import time
import traceback
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

if __package__ in {None, ""}:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from ida_mcp.config import (
        get_http_bind_host,
        get_http_connect_host,
        get_http_path,
        get_http_port,
        get_request_timeout,
    )
    from ida_mcp.proxy._server import server as proxy_server
else:
    from .config import (
        get_http_bind_host,
        get_http_connect_host,
        get_http_path,
        get_http_port,
        get_request_timeout,
    )
    from .proxy._server import server as proxy_server

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route


LOCALHOST = "127.0.0.1"
GATEWAY_BIND_HOST = get_http_bind_host()
GATEWAY_CONNECT_HOST = get_http_connect_host()
GATEWAY_PORT = get_http_port()
MCP_PATH = get_http_path()
REQUEST_TIMEOUT = get_request_timeout()

DEBUG_ENABLED = False
DEBUG_MAX_LEN = 1000

_instances: List[Dict[str, Any]] = []
_lock = threading.RLock()
_current_instance_port: Optional[int] = None
_call_locks: Dict[int, asyncio.Lock] = {}
_proxy_ready = False
_proxy_last_error: Optional[str] = None
_gateway_started_at = time.time()
_uvicorn_server = None

INSTANCE_HEALTH_HEALTHY = "healthy"
INSTANCE_HEALTH_DEGRADED = "degraded"
INSTANCE_HEALTH_UNREACHABLE = "unreachable"
INSTANCE_HEALTH_UNRESPONSIVE = "unresponsive"
INSTANCE_HEALTH_ERROR = "error"
INSTANCE_FAILURE_QUARANTINE_SECONDS = 60.0
INSTANCE_FAILURE_THRESHOLD = 2
MAIN_THREAD_STALE_SECONDS = 30.0


def _short(v: Any) -> str:
    try:
        s = json.dumps(v, ensure_ascii=False)
    except Exception:
        s = str(v)
    if len(s) > DEBUG_MAX_LEN:
        return s[:DEBUG_MAX_LEN] + "..."
    return s


def _debug_log(event: str, **fields: Any) -> None:  # pragma: no cover
    if not DEBUG_ENABLED:
        return
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    kv = " ".join(f"{k}={_short(v)}" for k, v in fields.items())
    print(f"[{ts}] [gateway] {event} {kv}", flush=True)


def set_debug(enable: bool) -> None:
    global DEBUG_ENABLED
    DEBUG_ENABLED = bool(enable)


def _now() -> float:
    return time.time()


def _find_instance_index_by_pid(pid: Any) -> Optional[int]:
    for idx, entry in enumerate(_instances):
        if entry.get("pid") == pid:
            return idx
    return None


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


async def _healthz(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "gateway": True,
            "proxy": _proxy_status(),
            "instance_count": len(_instances),
            "started_at": _gateway_started_at,
        }
    )


async def _instances_handler(_: Request) -> JSONResponse:
    with _lock:
        return JSONResponse([_public_instance_record(entry) for entry in _instances])


async def _current_instance_handler(_: Request) -> JSONResponse:
    with _lock:
        return JSONResponse({"port": _current_instance_port})


async def _debug_get(_: Request) -> JSONResponse:
    return JSONResponse({"enabled": DEBUG_ENABLED})


async def _debug_post(request: Request) -> JSONResponse:
    payload = await request.json()
    enable = bool(
        payload.get("enable") if "enable" in payload else payload.get("enabled", False)
    )
    set_debug(enable)
    return JSONResponse({"status": "ok", "enabled": DEBUG_ENABLED})


async def _proxy_status_handler(_: Request) -> JSONResponse:
    return JSONResponse(_proxy_status())


async def _ensure_proxy_handler(_: Request) -> JSONResponse:
    return JSONResponse(_proxy_status())


def _signal_gateway_shutdown() -> None:
    global _uvicorn_server
    if _uvicorn_server is not None:
        try:
            _uvicorn_server.should_exit = True
        except Exception:
            pass


async def _shutdown_handler(request: Request) -> JSONResponse:
    payload = await request.json() if request.method == "POST" else {}
    force = bool(payload.get("force", False))
    with _lock:
        instance_count = len(_instances)
    if instance_count > 0 and not force:
        return JSONResponse(
            {
                "error": "Gateway shutdown refused while IDA instances are still registered",
                "instance_count": instance_count,
            },
            status_code=409,
        )

    threading.Timer(0.05, _signal_gateway_shutdown).start()
    return JSONResponse(
        {
            "status": "ok",
            "message": "Gateway shutdown requested",
            "forced": force,
            "instance_count": instance_count,
        }
    )


async def _register_handler(request: Request) -> JSONResponse:
    payload = await request.json()
    if not {"pid", "port"}.issubset(payload):
        return JSONResponse({"error": "missing fields"}, status_code=400)
    with _lock:
        pid = payload["pid"]
        existing_idx = _find_instance_index_by_pid(pid)
        previous = _instances[existing_idx] if existing_idx is not None else None
        record = _with_gateway_metadata(payload, previous)
        if existing_idx is None:
            _instances.append(record)
        else:
            _instances[existing_idx] = record
    _debug_log("REGISTER", pid=payload.get("pid"), port=payload.get("port"))
    return JSONResponse({"status": "ok"})


async def _update_instance_handler(request: Request) -> JSONResponse:
    payload = await request.json()
    pid = payload.get("pid")
    port = payload.get("port")
    if pid is None and port is None:
        return JSONResponse({"error": "missing pid or port"}, status_code=400)

    with _lock:
        target = None
        for entry in _instances:
            if pid is not None and entry.get("pid") == pid:
                target = entry
                break
            if pid is None and port is not None and entry.get("port") == port:
                target = entry
                break
        if target is None:
            return JSONResponse({"error": "instance not found"}, status_code=404)
        for key, value in payload.items():
            if key in {"pid", "port"}:
                continue
            target[key] = value
    return JSONResponse({"status": "ok"})


async def _deregister_handler(request: Request) -> JSONResponse:
    global _current_instance_port
    payload = await request.json()
    pid = payload.get("pid")
    if pid is None:
        return JSONResponse({"error": "missing pid"}, status_code=400)
    with _lock:
        remaining = [e for e in _instances if e.get("pid") != pid]
        if _current_instance_port and not any(
            e.get("port") == _current_instance_port for e in remaining
        ):
            _current_instance_port = None
        _instances.clear()
        _instances.extend(remaining)
    _debug_log("DEREGISTER", pid=pid, remaining=len(_instances))
    return JSONResponse({"status": "ok"})


async def _select_instance_handler(request: Request) -> JSONResponse:
    global _current_instance_port
    payload = await request.json()
    port = payload.get("port")
    with _lock:
        if port is None:
            candidates = [
                entry for entry in _instances if _auto_routable_instance(entry)
            ]
            if not candidates:
                return JSONResponse(
                    {"error": "No ready instances to select from"}, status_code=404
                )
            sorted_instances = sorted(candidates, key=_instance_sort_key)
            _current_instance_port = sorted_instances[0].get("port")
        else:
            if not any(e.get("port") == port for e in _instances):
                return JSONResponse(
                    {"error": f"Instance with port {port} not found"}, status_code=404
                )
            _current_instance_port = port
    return JSONResponse({"status": "ok", "selected_port": _current_instance_port})


async def _call_handler(request: Request) -> JSONResponse:
    payload = await request.json()
    target_pid = payload.get("pid")
    target_port = payload.get("port")
    tool = payload.get("tool")
    params = payload.get("params") or {}
    if not tool:
        return JSONResponse({"error": "missing tool"}, status_code=400)

    with _lock:
        target = None
        if target_pid is not None:
            for entry in _instances:
                if entry.get("pid") == target_pid:
                    target = entry
                    break
        elif target_port is not None:
            for entry in _instances:
                if entry.get("port") == target_port:
                    target = entry
                    break
    if target is None:
        return JSONResponse({"error": "instance not found"}, status_code=404)

    preflight = _preflight_instance_route(target)
    if preflight is not None:
        return preflight

    port = target.get("port")
    if not isinstance(port, int):
        return JSONResponse({"error": "bad target port"}, status_code=500)

    req_timeout = payload.get("timeout")
    try:
        effective_timeout = (
            int(req_timeout)
            if req_timeout and int(req_timeout) > 0
            else REQUEST_TIMEOUT
        )
    except (ValueError, TypeError):
        effective_timeout = REQUEST_TIMEOUT

    try:
        with socket.create_connection((LOCALHOST, port), timeout=1.0):
            pass
    except (ConnectionRefusedError, OSError, socket.timeout) as exc:
        err_detail = f"Port {port} not reachable: {type(exc).__name__}: {exc}"
        _mark_instance_failure(
            port, INSTANCE_HEALTH_UNREACHABLE, err_detail, "connect", quarantine=True
        )
        return JSONResponse({"error": err_detail}, status_code=503)

    if port not in _call_locks:
        _call_locks[port] = asyncio.Lock()
    call_lock = _call_locks[port]

    try:
        await asyncio.wait_for(call_lock.acquire(), timeout=effective_timeout + 5)
    except TimeoutError:
        err_detail = f"Timed out waiting for call lock on port {port}"
        _mark_instance_failure(port, INSTANCE_HEALTH_DEGRADED, err_detail, "lock")
        return JSONResponse({"error": err_detail}, status_code=503)

    try:
        from fastmcp import Client  # type: ignore

        mcp_url = f"http://{LOCALHOST}:{port}/mcp/"
        async with Client(mcp_url, timeout=effective_timeout) as client:  # type: ignore
            resp = await client.call_tool(tool, params)
            data = None
            if hasattr(resp, "content") and resp.content:
                for item in resp.content:
                    text = getattr(item, "text", None)
                    if text:
                        try:
                            data = json.loads(text)
                            break
                        except (json.JSONDecodeError, TypeError):
                            continue
            if data is None and hasattr(resp, "data") and resp.data is not None:

                def norm(x: Any) -> Any:
                    if isinstance(x, list):
                        return [norm(i) for i in x]
                    if isinstance(x, dict):
                        return {k: norm(v) for k, v in x.items()}
                    if hasattr(x, "model_dump"):
                        return x.model_dump()
                    if hasattr(x, "__dict__") and x.__dict__:
                        return norm(vars(x))
                    return x

                data = norm(resp.data)
        _mark_instance_success(port)
        return JSONResponse({"tool": tool, "data": data})
    except Exception as exc:
        err_detail = f"{type(exc).__name__}: {exc}"
        health, status_code, error_kind = _classify_call_exception(exc)
        _mark_instance_failure(
            port, health, err_detail, error_kind, quarantine=status_code >= 503
        )
        _debug_log(
            "CALL_FAIL",
            tool=tool,
            target_port=port,
            error=err_detail,
            traceback=traceback.format_exc(),
        )
        return JSONResponse(
            {"error": f"call failed: {err_detail}"}, status_code=status_code
        )
    finally:
        call_lock.release()


def _build_internal_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            Route("/instances", _instances_handler, methods=["GET"]),
            Route("/current_instance", _current_instance_handler, methods=["GET"]),
            Route("/debug", _debug_get, methods=["GET"]),
            Route("/debug", _debug_post, methods=["POST"]),
            Route("/proxy_status", _proxy_status_handler, methods=["GET"]),
            Route("/ensure_proxy", _ensure_proxy_handler, methods=["POST"]),
            Route("/shutdown", _shutdown_handler, methods=["POST"]),
            Route("/register", _register_handler, methods=["POST"]),
            Route("/update_instance", _update_instance_handler, methods=["POST"]),
            Route("/deregister", _deregister_handler, methods=["POST"]),
            Route("/select_instance", _select_instance_handler, methods=["POST"]),
            Route("/call", _call_handler, methods=["POST"]),
        ]
    )


def _build_app() -> Starlette:
    mcp_app = proxy_server.http_app(path=MCP_PATH)  # type: ignore[attr-defined]

    @asynccontextmanager
    async def gateway_lifespan(app: Starlette):
        global _proxy_last_error, _proxy_ready

        _proxy_ready = False
        _proxy_last_error = None
        try:
            # FastMCP's Streamable HTTP session manager must run in the parent
            # Starlette lifespan so request scopes inherit the initialized state.
            if hasattr(mcp_app, "lifespan"):
                async with mcp_app.lifespan(app):
                    _proxy_ready = True
                    yield
            else:
                _proxy_ready = True
                yield
        except Exception as exc:
            _proxy_last_error = str(exc)
            raise
        finally:
            _proxy_ready = False

    return Starlette(
        routes=[
            Mount("/internal", app=_build_internal_app()),
            Mount("/", app=mcp_app),
        ],
        lifespan=gateway_lifespan,
    )


def serve_forever(host: str = GATEWAY_BIND_HOST, port: int = GATEWAY_PORT) -> None:
    import uvicorn

    global _uvicorn_server
    app = _build_app()
    print(f"[IDA-MCP-Gateway] listening on http://{host}:{port}", flush=True)
    print(
        f"[IDA-MCP-Gateway] MCP available at http://{GATEWAY_CONNECT_HOST}:{port}{MCP_PATH}",
        flush=True,
    )
    config = uvicorn.Config(
        app, host=host, port=port, log_level="warning", access_log=False
    )
    _uvicorn_server = uvicorn.Server(config)
    _uvicorn_server.run()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IDA MCP standalone gateway")
    parser.add_argument(
        "--host", default=GATEWAY_BIND_HOST, help="Host to bind (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=GATEWAY_PORT, help="Port to bind (default: 11338)"
    )
    args = parser.parse_args()
    serve_forever(args.host, args.port)
