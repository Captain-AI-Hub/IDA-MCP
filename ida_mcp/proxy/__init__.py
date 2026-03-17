"""Lightweight exports for the proxy package.

The package intentionally avoids importing the FastMCP server on import so CLI
helpers and tests can reuse lifecycle/client code without proxy initialization.
"""
from __future__ import annotations

from typing import Any

__all__ = ["server", "start_http_proxy", "stop_http_proxy", "is_http_proxy_running", "get_http_url"]


def __getattr__(name: str) -> Any:
    if name == "server":
        from ._server import server

        return server
    if name in {"start_http_proxy", "stop_http_proxy", "is_http_proxy_running", "get_http_url"}:
        from . import http_server

        return getattr(http_server, name)
    raise AttributeError(name)
