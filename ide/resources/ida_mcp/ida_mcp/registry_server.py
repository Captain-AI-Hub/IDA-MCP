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
    import ida_mcp.instance_registry as instance_registry
    import ida_mcp.registry_routes as registry_routes
    from ida_mcp.registry_routes import (
        _call_handler,
        _debug_get,
        _debug_post,
        _deregister_handler,
        _ensure_proxy_handler,
        _healthz,
        _instances_handler,
        _proxy_status_handler,
        _register_handler,
        _shutdown_handler,
        _update_instance_handler,
    )
else:
    from .config import (
        get_http_bind_host,
        get_http_connect_host,
        get_http_path,
        get_http_port,
        get_request_timeout,
    )
    from .proxy._server import server as proxy_server
    from . import instance_registry, registry_routes
    from .registry_routes import (
        _call_handler,
        _debug_get,
        _debug_post,
        _deregister_handler,
        _ensure_proxy_handler,
        _healthz,
        _instances_handler,
        _proxy_status_handler,
        _register_handler,
        _shutdown_handler,
        _update_instance_handler,
    )

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


def _build_internal_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            Route("/instances", _instances_handler, methods=["GET"]),
            Route("/debug", _debug_get, methods=["GET"]),
            Route("/debug", _debug_post, methods=["POST"]),
            Route("/proxy_status", _proxy_status_handler, methods=["GET"]),
            Route("/ensure_proxy", _ensure_proxy_handler, methods=["POST"]),
            Route("/shutdown", _shutdown_handler, methods=["POST"]),
            Route("/register", _register_handler, methods=["POST"]),
            Route("/update_instance", _update_instance_handler, methods=["POST"]),
            Route("/deregister", _deregister_handler, methods=["POST"]),
            Route("/call", _call_handler, methods=["POST"]),
        ]
    )


def _build_app() -> Starlette:
    mcp_app = proxy_server.http_app(path=MCP_PATH)  # type: ignore[attr-defined]

    @asynccontextmanager
    async def gateway_lifespan(app: Starlette):
        instance_registry._proxy_ready = False
        instance_registry._proxy_last_error = None
        try:
            # FastMCP's Streamable HTTP session manager must run in the parent
            # Starlette lifespan so request scopes inherit the initialized state.
            if hasattr(mcp_app, "lifespan"):
                async with mcp_app.lifespan(app):
                    instance_registry._proxy_ready = True
                    yield
            else:
                instance_registry._proxy_ready = True
                yield
        except Exception as exc:
            instance_registry._proxy_last_error = str(exc)
            raise
        finally:
            instance_registry._proxy_ready = False

    return Starlette(
        routes=[
            Mount("/internal", app=_build_internal_app()),
            Mount("/", app=mcp_app),
        ],
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
    registry_routes._uvicorn_server.run()


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
