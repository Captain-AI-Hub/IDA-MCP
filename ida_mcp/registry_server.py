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
        is_mcp_json_response_enabled,
        is_mcp_sessionless_enabled,
    )
    from ida_mcp.proxy._server import server as proxy_server
    from ida_mcp.protocol_guard import LegacyProtocolGateMiddleware
    import ida_mcp.instance_registry as instance_registry
    import ida_mcp.registry as registry_client
    import ida_mcp.registry_routes as registry_routes
    from ida_mcp.registry_routes import (
        _call_handler,
        _current_instance_handler,
        _debug_get,
        _debug_post,
        _deregister_handler,
        _ensure_gateway_proxy_handler,
        _healthz,
        _instances_handler,
        _gateway_proxy_status_handler,
        _register_handler,
        _select_instance_handler,
        _shutdown_handler,
        _update_instance_handler,
        is_gateway_request_authorized,
    )
else:
    from .config import (
        get_http_bind_host,
        get_http_connect_host,
        get_http_path,
        get_http_port,
        get_request_timeout,
        is_mcp_json_response_enabled,
        is_mcp_sessionless_enabled,
    )
    from .proxy._server import server as proxy_server
    from .protocol_guard import LegacyProtocolGateMiddleware
    from . import instance_registry, registry as registry_client, registry_routes
    from .registry_routes import (
        _call_handler,
        _current_instance_handler,
        _debug_get,
        _debug_post,
        _deregister_handler,
        _ensure_gateway_proxy_handler,
        _healthz,
        _instances_handler,
        _gateway_proxy_status_handler,
        _register_handler,
        _select_instance_handler,
        _shutdown_handler,
        _update_instance_handler,
        is_gateway_request_authorized,
    )

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route


LOCALHOST = "127.0.0.1"
GATEWAY_BIND_HOST = get_http_bind_host()
GATEWAY_CONNECT_HOST = get_http_connect_host()
GATEWAY_PORT = get_http_port()
MCP_PATH = get_http_path()
REQUEST_TIMEOUT = get_request_timeout()


class _GatewayAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if not is_gateway_request_authorized(request):
            return JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)


def _build_internal_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            Route("/instances", _instances_handler, methods=["GET"]),
            Route("/current_instance", _current_instance_handler, methods=["GET"]),
            Route("/debug", _debug_get, methods=["GET"]),
            Route("/debug", _debug_post, methods=["POST"]),
            Route("/gateway_proxy_status", _gateway_proxy_status_handler, methods=["GET"]),
            Route("/ensure_gateway_proxy", _ensure_gateway_proxy_handler, methods=["POST"]),
            Route("/shutdown", _shutdown_handler, methods=["POST"]),
            Route("/register", _register_handler, methods=["POST"]),
            Route("/update_instance", _update_instance_handler, methods=["POST"]),
            Route("/deregister", _deregister_handler, methods=["POST"]),
            Route("/select_instance", _select_instance_handler, methods=["POST"]),
            Route("/call", _call_handler, methods=["POST"]),
        ]
    )


def _build_app() -> Starlette:
    # Tool calls do not need long-lived server-side sessions. Stateless HTTP
    # also lets clients recover cleanly after a gateway restart instead of
    # sending an obsolete Mcp-Session-Id and receiving "Session not found".
    mcp_app = proxy_server.http_app(  # type: ignore[attr-defined]
        path=MCP_PATH,
        stateless_http=is_mcp_sessionless_enabled(),
        json_response=is_mcp_json_response_enabled(),
        # The MCP 2026-07-28 transport performs per-request negotiation and
        # dispatches modern requests without initialize/session state.
        session_idle_timeout=None,
        # Reject handshake-era clients outright when mcp_legacy_protocol=false.
        middleware=[Middleware(LegacyProtocolGateMiddleware)],
    )

    @asynccontextmanager
    async def gateway_lifespan(app: Starlette):
        instance_registry._gateway_proxy_ready = False
        instance_registry._gateway_proxy_last_error = None
        try:
            # FastMCP's Streamable HTTP session manager must run in the parent
            # Starlette lifespan so request scopes inherit the initialized state.
            if hasattr(mcp_app, "lifespan"):
                async with mcp_app.lifespan(app):
                    instance_registry._gateway_proxy_ready = True
                    yield
            else:
                instance_registry._gateway_proxy_ready = True
                yield
        except Exception as exc:
            instance_registry._gateway_proxy_last_error = str(exc)
            raise
        finally:
            instance_registry._gateway_proxy_ready = False

    return Starlette(
        routes=[
            Mount("/internal", app=_build_internal_app()),
            Mount("/", app=mcp_app),
        ],
        middleware=[Middleware(_GatewayAuthMiddleware)],
        lifespan=gateway_lifespan,
    )


def serve_forever(host: str = GATEWAY_BIND_HOST, port: int = GATEWAY_PORT) -> None:
    import uvicorn

    app = _build_app()
    print(f"[IDA-MCP-Gateway] listening on http://{host}:{port}", flush=True)
    print(
        f"[IDA-MCP-Gateway] MCP available at http://{GATEWAY_CONNECT_HOST}:{port}{MCP_PATH}",
        flush=True,
    )
    config = uvicorn.Config(
        app, host=host, port=port, log_level="warning", access_log=False
    )
    registry_routes._uvicorn_server = uvicorn.Server(config)
    registry_client.write_gateway_pid()
    try:
        registry_routes._uvicorn_server.run()
    finally:
        registry_client.remove_gateway_pid()


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
