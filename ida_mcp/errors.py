"""Shared error helpers for proxy/control surfaces."""
from __future__ import annotations

from typing import Any


def error_payload(code: str, message: str, **details: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details:
        payload["error"]["details"] = details
    return payload


def normalize_error_payload(
    error: Any,
    default_code: str,
    default_message: str | None = None,
    **details: Any,
) -> dict[str, Any]:
    if isinstance(error, dict):
        nested = error.get("error")
        if isinstance(nested, dict) and "code" in nested and "message" in nested:
            payload = {"error": dict(nested)}
            existing_details = payload["error"].get("details")
            if details:
                if isinstance(existing_details, dict):
                    merged = dict(existing_details)
                    merged.update(details)
                    payload["error"]["details"] = merged
                else:
                    payload["error"]["details"] = details
            return payload

    message = default_message if default_message is not None else str(error)
    return error_payload(default_code, message, raw_error=error, **details)
