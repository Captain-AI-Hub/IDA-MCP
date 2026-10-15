"""HTTP client for the in-instance JSON-RPC bridge."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .errors import error_payload

_PROBE_TIMEOUT = 2.0


def _base_url(entry: Dict[str, Any]) -> str:
    host = entry.get("host") or "127.0.0.1"
    port = int(entry.get("port") or 0)
    return f"http://{host}:{port}"


def _headers(entry: Dict[str, Any]) -> Dict[str, str]:
    return {"Content-Type": "application/json"}


def _request(
    entry: Dict[str, Any],
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Perform one bridge request; returns the parsed JSON document."""
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    request = urllib.request.Request(
        _base_url(entry) + path,
        data=data,
        headers=_headers(entry),
        method=method,
    )
    effective_timeout = _PROBE_TIMEOUT if timeout is None else max(float(timeout), 0.5)
    with urllib.request.urlopen(request, timeout=effective_timeout) as response:
        body = response.read()
    document = json.loads(body.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError("bridge returned a non-object JSON payload")
    return document


def check_error(document: Dict[str, Any]) -> Dict[str, Any]:
    """Raise a BridgeError when the bridge returned an error payload."""
    error = document.get("error")
    if isinstance(error, dict):
        raise BridgeError(
            error.get("code", "bridge_error"),
            error.get("message", "bridge error"),
            details=error.get("details"),
        )
    return document


class BridgeError(RuntimeError):
    def __init__(self, code: str, message: str, details: Any = None):
        super().__init__(message)
        self.code = code
        self.details = details

    def payload(self) -> Dict[str, Any]:
        return error_payload(self.code, str(self), details=self.details)


# ============================================================================
# Public helpers (all operate on registry entries)
# ============================================================================


def is_alive(entry: Dict[str, Any], timeout: float = _PROBE_TIMEOUT) -> bool:
    try:
        document = _request(entry, "GET", "/healthz", timeout=timeout)
        return bool(document.get("ok"))
    except (OSError, ValueError):
        return False


def get_meta(entry: Dict[str, Any], timeout: float = _PROBE_TIMEOUT) -> Dict[str, Any]:
    return check_error(_request(entry, "GET", "/meta", timeout=timeout)).get("result") or {}


def call_tool(
    entry: Dict[str, Any],
    tool: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: Optional[float] = None,
) -> Any:
    payload = {"tool": tool, "params": params or {}}
    if timeout is not None:
        payload["timeout"] = float(timeout)
    document = _request(entry, "POST", "/rpc", payload=payload, timeout=timeout)
    return check_error(document).get("result")


def docs_modules(entry: Dict[str, Any], timeout: float = 30.0) -> list:
    return check_error(_request(entry, "GET", "/docs/modules", timeout=timeout)).get("result") or []


def docs_snapshot(
    entry: Dict[str, Any],
    module: str,
    timeout: float = 60.0,
) -> Dict[str, Any]:
    document = _request(entry, "POST", "/docs", payload={"module": module}, timeout=timeout)
    return check_error(document).get("result") or {}


def request_shutdown(
    entry: Dict[str, Any],
    save: bool = True,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    document = _request(
        entry, "POST", "/shutdown", payload={"save": bool(save)}, timeout=timeout
    )
    return check_error(document).get("result") or {}


def describe_error(exc: Exception) -> Dict[str, Any]:
    """Normalize any client-side failure into an error payload."""
    if isinstance(exc, BridgeError):
        return exc.payload()
    if isinstance(exc, urllib.error.HTTPError):
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
        except OSError:
            pass
        return error_payload(
            "bridge_http_error",
            f"bridge HTTP {exc.code}: {exc.reason}" + (f" — {detail}" if detail else ""),
        )
    if isinstance(exc, urllib.error.URLError):
        return error_payload(
            "instance_unreachable",
            f"IDA instance not reachable: {exc.reason}",
        )
    return error_payload("bridge_error", f"{type(exc).__name__}: {exc}")
