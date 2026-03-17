"""Lightweight control helpers for CLI and scripts.

This module intentionally avoids importing FastMCP server setup so it can be
used by command.py, scripts, and tests without triggering proxy initialization.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional

from . import registry
from .config import (
    get_coordinator_host,
    get_coordinator_port,
    get_http_connect_host,
    get_http_path,
    get_http_port,
    get_request_timeout,
)
from .proxy._http import http_post
from .proxy._state import choose_port, get_instances, is_registered_port, is_valid_port
from .errors import error_payload, normalize_error_payload


def gateway_status_payload() -> dict[str, Any]:
    gateway = registry.get_registry_server_status()
    proxy = registry.get_http_proxy_status()
    instances = registry.get_instances() if gateway.get("alive") else []
    return {
        "gateway": gateway,
        "proxy": proxy,
        "instances": instances,
        "count": len(instances),
        "coordinator": {
            "host": get_coordinator_host(),
            "port": get_coordinator_port(),
        },
        "http_proxy": {
            "host": get_http_connect_host(),
            "port": get_http_port(),
            "path": get_http_path(),
        },
    }


def ensure_gateway_running(startup_timeout: float = 3.0) -> dict[str, Any]:
    ok = registry.ensure_registry_server(startup_timeout=startup_timeout)
    proxy_ok = registry.ensure_http_proxy_running(startup_timeout=startup_timeout)
    payload = gateway_status_payload()
    payload["ok"] = bool(ok)
    payload["proxy_ok"] = bool(proxy_ok or not payload.get("proxy", {}).get("enabled", True))
    if not payload["ok"]:
        return error_payload(
            "gateway_start_failed",
            "Failed to start the standalone gateway.",
            status=payload,
        )
    return payload


def restart_gateway(startup_timeout: float = 3.0, force: bool = False) -> dict[str, Any]:
    if registry.get_registry_server_status().get("alive"):
        stopped = registry.shutdown_gateway(force=force, timeout=startup_timeout)
        if "error" in stopped:
            return error_payload(
                "gateway_restart_failed",
                "Failed to stop the standalone gateway before restart.",
                result=stopped,
            )
        deadline = time.monotonic() + max(startup_timeout, 0.5)
        while time.monotonic() < deadline:
            if not registry.get_registry_server_status().get("alive"):
                break
            time.sleep(0.1)
    payload = ensure_gateway_running(startup_timeout=startup_timeout)
    if "error" in payload:
        return payload
    payload["requested"] = "restart"
    return payload


def select_target_port(port: Optional[int] = None) -> dict[str, Any]:
    if port is not None:
        if not is_valid_port(port):
            return error_payload(
                "invalid_port",
                f"Invalid port: {port}. Port must be between 1 and 65535.",
            )
        if not is_registered_port(port):
            return error_payload(
                "instance_not_found",
                f"Port {port} was not found in the registered IDA instances.",
            )
        selected = port
    else:
        selected = choose_port()
        if selected is None:
            return error_payload(
                "no_instances",
                "No registered IDA instances are available.",
            )

    instance = next((entry for entry in get_instances() if entry.get("port") == selected), None)
    return {
        "selected_port": selected,
        "instance": instance,
    }


def call_tool(
    tool_name: str,
    params: Optional[dict[str, Any]] = None,
    port: Optional[int] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    selection = select_target_port(port)
    if "error" in selection:
        return selection

    body: dict[str, Any] = {
        "tool": tool_name,
        "params": params or {},
        "port": selection["selected_port"],
    }
    if timeout and timeout > 0:
        body["timeout"] = timeout
    raw = http_post("/call", body, timeout=(timeout + 15) if timeout and timeout > 0 else None)
    if not isinstance(raw, dict):
        return error_payload("gateway_unavailable", "Failed to connect to the gateway.")
    if "error" in raw:
        return normalize_error_payload(
            raw,
            "tool_call_failed",
            f"Gateway rejected tool call for {tool_name}.",
            tool=tool_name,
            port=selection["selected_port"],
        )
    return {
        "tool": tool_name,
        "selected_port": selection["selected_port"],
        "instance": selection.get("instance"),
        "data": raw.get("data", raw),
    }


def open_ida(file_path: str, extra_args: Optional[list[str]] = None) -> dict[str, Any]:
    from .proxy import lifecycle

    result = lifecycle.open_in_ida(file_path, extra_args=extra_args)
    if "error" in result:
        return error_payload("ida_open_failed", str(result["error"]), file_path=file_path)
    return result


def close_ida(
    save: bool = True,
    port: Optional[int] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    from .proxy import lifecycle

    selection = select_target_port(port)
    if "error" in selection:
        return selection
    result = lifecycle.close_ida(save=save, port=selection["selected_port"], timeout=timeout)
    if "error" in result:
        return error_payload("ida_close_failed", str(result["error"]), port=selection["selected_port"])
    return {
        "selected_port": selection["selected_port"],
        "instance": selection.get("instance"),
        "data": result,
    }


def shutdown_gateway(force: bool = False, timeout: Optional[float] = None) -> dict[str, Any]:
    result = registry.shutdown_gateway(force=force, timeout=timeout)
    if "error" in result:
        return error_payload("gateway_stop_failed", str(result["error"]), result=result)
    return result


def list_ida_instances() -> dict[str, Any]:
    gateway = registry.get_registry_server_status()
    instances = registry.get_instances() if gateway.get("alive") else []
    return {
        "gateway_alive": bool(gateway.get("alive")),
        "count": len(instances),
        "instances": instances,
    }


def list_resources(port: Optional[int] = None, timeout: Optional[int] = None) -> dict[str, Any]:
    selection = select_target_port(port)
    if "error" in selection:
        return selection
    try:
        resources = asyncio.run(_list_resources_async(selection["selected_port"], timeout=timeout))
    except ModuleNotFoundError as exc:
        return error_payload(
            "fastmcp_missing",
            "fastmcp is required for direct resource access. Install the project dependencies in the Python environment running command.py.",
            missing_module=getattr(exc, "name", None),
        )
    except Exception as exc:
        return error_payload(
            "resource_list_failed",
            str(exc),
            port=selection["selected_port"],
        )
    resources["selected_port"] = selection["selected_port"]
    resources["instance"] = selection.get("instance")
    return resources


def read_resource(uri: str, port: Optional[int] = None, timeout: Optional[int] = None) -> dict[str, Any]:
    selection = select_target_port(port)
    if "error" in selection:
        return selection
    try:
        payload = asyncio.run(_read_resource_async(uri, selection["selected_port"], timeout=timeout))
    except ModuleNotFoundError as exc:
        return error_payload(
            "fastmcp_missing",
            "fastmcp is required for direct resource access. Install the project dependencies in the Python environment running command.py.",
            uri=uri,
            port=selection["selected_port"],
            missing_module=getattr(exc, "name", None),
        )
    except Exception as exc:
        return error_payload(
            "resource_read_failed",
            str(exc),
            uri=uri,
            port=selection["selected_port"],
        )
    payload["selected_port"] = selection["selected_port"]
    payload["instance"] = selection.get("instance")
    return payload


async def _list_resources_async(port: int, timeout: Optional[int] = None) -> dict[str, Any]:
    from fastmcp import Client  # type: ignore

    client_timeout = timeout if timeout and timeout > 0 else get_request_timeout()
    async with Client(f"http://127.0.0.1:{port}/mcp/", timeout=client_timeout) as client:  # type: ignore[arg-type]
        result = await client.list_resources()

    resources: list[dict[str, Any]] = []
    templates: list[dict[str, Any]] = []
    if isinstance(result, list):
        for entry in result:
            uri_template = getattr(entry, "uriTemplate", None)
            if uri_template:
                templates.append(
                    {
                        "uri_template": uri_template,
                        "name": getattr(entry, "name", None),
                        "description": getattr(entry, "description", None),
                    }
                )
            else:
                resources.append(
                    {
                        "uri": getattr(entry, "uri", str(entry)),
                        "name": getattr(entry, "name", None),
                        "description": getattr(entry, "description", None),
                    }
                )
    return {
        "resources": resources,
        "templates": templates,
        "total": len(resources) + len(templates),
    }


async def _read_resource_async(uri: str, port: int, timeout: Optional[int] = None) -> dict[str, Any]:
    from fastmcp import Client  # type: ignore

    client_timeout = timeout if timeout and timeout > 0 else get_request_timeout()
    async with Client(f"http://127.0.0.1:{port}/mcp/", timeout=client_timeout) as client:  # type: ignore[arg-type]
        result = await client.read_resource(uri)
    return {
        "uri": uri,
        "data": _decode_resource_contents(result),
    }


def _decode_resource_contents(result: Any) -> Any:
    if not isinstance(result, list):
        return result

    for content in result:
        text = getattr(content, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        blob = getattr(content, "blob", None)
        if blob:
            return {
                "type": "blob",
                "size": len(blob),
            }
    return [str(item) for item in result]
