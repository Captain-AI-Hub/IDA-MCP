"""Runtime helpers that coordinate optional standalone transports."""
from __future__ import annotations


def start_http_proxy_if_gateway() -> str | None:
    """Ensure the client-facing HTTP proxy daemon is running when enabled."""
    from . import registry
    from .config import get_http_url, is_http_enabled

    if not is_http_enabled():
        return None

    if registry.ensure_http_proxy_running():
        return get_http_url()

    return None
