"""Lightweight exports for the proxy package.

The package intentionally avoids importing the FastMCP server on import so CLI
helpers and tests can reuse lifecycle/client code without proxy initialization.
"""
from __future__ import annotations

from typing import Any

__all__ = ["server"]


def __getattr__(name: str) -> Any:
    if name == "server":
        from ._server import server

        return server
    raise AttributeError(name)
