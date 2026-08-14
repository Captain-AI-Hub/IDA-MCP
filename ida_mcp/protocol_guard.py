"""ASGI gate that rejects handshake-era MCP requests when legacy protocol is off.

MCP 2026-07-28 removed the ``initialize``/``initialized`` handshake and the
``Mcp-Session-Id`` header (SEP-2575, SEP-2567). The SDK still serves those
legacy clients for backward compatibility; when ``mcp_legacy_protocol`` is
disabled this middleware rejects them so the deployment speaks only the
modern stateless protocol.
"""
from __future__ import annotations

import json
from typing import Any, List

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import is_mcp_legacy_protocol_enabled

try:  # mcp_types ships with the MCP SDK
    from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, LATEST_PROTOCOL_VERSION
except Exception:  # pragma: no cover - defensive fallback
    HANDSHAKE_PROTOCOL_VERSIONS = (
        "2024-11-05",
        "2025-03-26",
        "2025-06-18",
        "2025-11-25",
    )
    LATEST_PROTOCOL_VERSION = "2026-07-28"

_LEGACY_METHODS = frozenset({"initialize", "notifications/initialized"})
_PROTOCOL_VERSION_HEADER = b"mcp-protocol-version"


def _is_legacy_payload(payload: Any) -> bool:
    """Whether a decoded JSON-RPC payload belongs to the handshake era."""
    if isinstance(payload, dict):
        return payload.get("method") in _LEGACY_METHODS
    if isinstance(payload, list):
        return any(_is_legacy_payload(item) for item in payload)
    return False


class LegacyProtocolGateMiddleware:
    """Reject pre-2026 initialize/session requests when legacy mode is off."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or is_mcp_legacy_protocol_enabled()
        ):
            await self.app(scope, receive, send)
            return

        # Fast path: a handshake-era MCP-Protocol-Version header is conclusive.
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        version = headers.get(_PROTOCOL_VERSION_HEADER)
        if version is not None and version.decode("latin-1").strip() in (
            HANDSHAKE_PROTOCOL_VERSIONS
        ):
            await self._reject(send, None)
            return

        # 2025-03-26-era clients send no version header, so inspect the body.
        buffered: List[Message] = []
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] != "http.request" or not message.get("more_body"):
                break

        payload: Any = None
        body = b"".join(
            m.get("body", b"") for m in buffered if m["type"] == "http.request"
        )
        if body:
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = None

        if _is_legacy_payload(payload):
            await self._reject(send, payload)
            return

        index = 0

        async def replay_receive() -> Message:
            nonlocal index
            if index < len(buffered):
                message = buffered[index]
                index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _reject(self, send: Send, payload: Any) -> None:
        request_id = payload.get("id") if isinstance(payload, dict) else None
        message = (
            "Legacy MCP protocol (initialize/session) is disabled on this "
            f"server; speak MCP {LATEST_PROTOCOL_VERSION} instead."
        )
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": message},
            }
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})
