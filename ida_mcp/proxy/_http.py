"""HTTP helpers for communicating with the standalone gateway."""
from __future__ import annotations

import json
import urllib.request
from typing import Any

from ..config import get_gateway_internal_url, get_request_timeout
from ..registry import ensure_registry_server


def http_get(path: str) -> Any:
    """GET request against the gateway internal API."""
    if not ensure_registry_server():
        return None
    try:
        with urllib.request.urlopen(get_gateway_internal_url() + path, timeout=get_request_timeout()) as r:
            return json.loads(r.read().decode('utf-8') or 'null')
    except Exception:
        return None


def http_post(path: str, obj: dict, timeout: int | None = None) -> Any:
    """POST request against the gateway internal API."""
    if not ensure_registry_server():
        return {"error": "Gateway unavailable"}
    data = json.dumps(obj).encode('utf-8')
    req = urllib.request.Request(
        get_gateway_internal_url() + path,
        data=data,
        method='POST',
        headers={'Content-Type': 'application/json'}
    )
    effective_timeout = timeout if timeout and timeout > 0 else get_request_timeout()
    try:
        with urllib.request.urlopen(req, timeout=effective_timeout) as r:
            return json.loads(r.read().decode('utf-8') or 'null')
    except Exception as e:
        return {"error": str(e)}
