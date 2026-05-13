"""Internal gateway route handlers."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
import traceback
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from . import instance_registry as registry
from .config import get_request_timeout


LOCALHOST = "127.0.0.1"
REQUEST_TIMEOUT = get_request_timeout()
DEBUG_ENABLED = False
DEBUG_MAX_LEN = 1000
DEBUG_INTERNAL_TOKEN = "ida-mcp-debug"
_uvicorn_server = None


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


async def _healthz(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "gateway": True,
            "proxy": registry._proxy_status(),
            "instance_count": len(registry._instances),
            "started_at": registry._gateway_started_at,
        }
    )


async def _instances_handler(_: Request) -> JSONResponse:
    with registry._lock:
        registry._reap_dead_instances()
        registry._reap_stale_pending_instances()
        return JSONResponse(
            [registry._public_instance_record(entry) for entry in registry._instances]
        )


async def _debug_get(_: Request) -> JSONResponse:
    return JSONResponse({"enabled": DEBUG_ENABLED})


async def _debug_post(request: Request) -> JSONResponse:
    if request.headers.get("X-Internal-Token") != DEBUG_INTERNAL_TOKEN:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    payload = await request.json()
    enable = bool(
        payload.get("enable") if "enable" in payload else payload.get("enabled", False)
    )
    set_debug(enable)
    return JSONResponse({"status": "ok", "enabled": DEBUG_ENABLED})


async def _proxy_status_handler(_: Request) -> JSONResponse:
    return JSONResponse(registry._proxy_status())


async def _ensure_proxy_handler(_: Request) -> JSONResponse:
    return JSONResponse(registry._proxy_status())


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
    with registry._lock:
        instance_count = len(registry._instances)
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
    with registry._lock:
        pid = payload["pid"]
        payload["last_seen_at"] = _now()
        existing_idx = registry._find_instance_index_by_pid(pid)
        previous = registry._instances[existing_idx] if existing_idx is not None else None
        record = registry._with_gateway_metadata(payload, previous)
        if existing_idx is None:
            registry._instances.append(record)
        else:
            registry._instances[existing_idx] = record
    _debug_log("REGISTER", pid=payload.get("pid"), port=payload.get("port"))
    return JSONResponse({"status": "ok"})


async def _update_instance_handler(request: Request) -> JSONResponse:
    payload = await request.json()
    pid = payload.get("pid")
    port = payload.get("port")
    if pid is None and port is None:
        return JSONResponse({"error": "missing pid or port"}, status_code=400)

    with registry._lock:
        target = None
        for entry in registry._instances:
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
        target["last_seen_at"] = _now()
    return JSONResponse({"status": "ok"})


async def _deregister_handler(request: Request) -> JSONResponse:
    payload = await request.json()
    pid = payload.get("pid")
    if pid is None:
        return JSONResponse({"error": "missing pid"}, status_code=400)
    with registry._lock:
        remaining = [e for e in registry._instances if e.get("pid") != pid]
        if registry._current_instance_port and not any(
            e.get("port") == registry._current_instance_port for e in remaining
        ):
            registry._current_instance_port = None
        registry._instances.clear()
        registry._instances.extend(remaining)
    _debug_log("DEREGISTER", pid=pid, remaining=len(registry._instances))
    return JSONResponse({"status": "ok"})


async def _call_handler(request: Request) -> JSONResponse:
    payload = await request.json()
    target_pid = payload.get("pid")
    target_port = payload.get("port")
    tool = payload.get("tool")
    params = payload.get("params") or {}
    if not tool:
        return JSONResponse({"error": "missing tool"}, status_code=400)

    with registry._lock:
        registry._reap_dead_instances()
        registry._reap_stale_pending_instances()
        target = None
        if target_pid is not None:
            for entry in registry._instances:
                if entry.get("pid") == target_pid:
                    target = entry
                    break
        elif target_port is not None:
            for entry in registry._instances:
                if entry.get("port") == target_port:
                    target = entry
                    break
    if target is None:
        return JSONResponse({"error": "instance not found"}, status_code=404)

    preflight = registry._preflight_instance_route(target)
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
        registry._mark_instance_failure(
            port,
            registry.INSTANCE_HEALTH_UNREACHABLE,
            err_detail,
            "connect",
            quarantine=True,
        )
        return JSONResponse({"error": err_detail}, status_code=503)

    with registry._CALL_LOCKS_GUARD:
        if port not in registry._call_locks:
            registry._call_locks[port] = asyncio.Lock()
        call_lock = registry._call_locks[port]

    acquired = False
    try:
        await asyncio.wait_for(call_lock.acquire(), timeout=effective_timeout + 5)
        acquired = True
    except TimeoutError:
        err_detail = f"Timed out waiting for call lock on port {port}"
        registry._mark_instance_failure(
            port, registry.INSTANCE_HEALTH_DEGRADED, err_detail, "lock"
        )
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
        registry._mark_instance_success(port)
        return JSONResponse({"tool": tool, "data": data})
    except Exception as exc:
        err_detail = f"{type(exc).__name__}: {exc}"
        health, status_code, error_kind = registry._classify_call_exception(exc)
        registry._mark_instance_failure(
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
        if acquired:
            call_lock.release()
