"""Proxy tool registration for forwarded IDA operations."""
from __future__ import annotations

import functools
import inspect
from typing import Annotated, Any, List, Optional, get_type_hints

try:
    from pydantic import Field
except ImportError:  # pragma: no cover
    Field = lambda **kwargs: None  # type: ignore

from ..config import is_unsafe_enabled
from ..rpc import ToolSpec, get_tool_specs
from ..server_factory import _ensure_api_modules_loaded
from ._state import forward
from . import lifecycle


_PORT_ANNOTATION = Annotated[Optional[int], Field(description="Instance port override")]
_TIMEOUT_ANNOTATION = Annotated[Optional[int], Field(description="Timeout in seconds")]
_PROXY_MANAGED_TOOL_NAMES = {"check_connection", "list_instances", "close_ida"}


def _proxy_parameter(name: str, annotation: Any, description: str) -> inspect.Parameter:
    return inspect.Parameter(
        name=name,
        kind=inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation=Annotated[annotation, Field(description=description)],
    )


def _build_forward_signature(spec: ToolSpec) -> inspect.Signature:
    source_signature = inspect.signature(spec.fn)
    params = list(source_signature.parameters.values())
    params.append(_proxy_parameter("port", Optional[int], "Instance port override"))
    params.append(_proxy_parameter("timeout", Optional[int], "Timeout in seconds"))
    return source_signature.replace(parameters=params)


def _build_forward_wrapper(spec: ToolSpec) -> Any:
    source_signature = inspect.signature(spec.fn)
    source_param_names = tuple(source_signature.parameters.keys())
    source_hints = get_type_hints(spec.fn, include_extras=True)

    @functools.wraps(spec.fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        port = kwargs.pop("port", None)
        timeout = kwargs.pop("timeout", None)
        bound = source_signature.bind_partial(*args, **kwargs)
        params = {
            name: bound.arguments[name]
            for name in source_param_names
            if name in bound.arguments
        }
        return forward(spec.name, params, port, timeout=timeout)

    wrapper.__signature__ = _build_forward_signature(spec)  # type: ignore[attr-defined]
    wrapper.__annotations__ = dict(source_hints)
    wrapper.__annotations__["port"] = _PORT_ANNOTATION
    wrapper.__annotations__["timeout"] = _TIMEOUT_ANNOTATION
    return wrapper


def _register_forwarded_backend_tools(server: Any, unsafe_enabled: bool) -> None:
    _ensure_api_modules_loaded()

    for spec in sorted(get_tool_specs().values(), key=lambda item: item.name):
        if spec.name in _PROXY_MANAGED_TOOL_NAMES:
            continue
        if spec.unsafe and not unsafe_enabled:
            continue

        wrapper = _build_forward_wrapper(spec)
        server.tool(description=spec.description)(wrapper)


def register_tools(server: Any) -> None:
    """Register all proxy-exposed forwarding tools."""
    unsafe_enabled = is_unsafe_enabled()
    _register_forwarded_backend_tools(server, unsafe_enabled)

    @server.tool(description="Launch IDA Pro with the specified file. Automatically attempts to load IDA-MCP plugin.")
    def open_in_ida(
        file_path: Annotated[str, Field(description="Path to the file to open (executable or IDB)")],
        extra_args: Annotated[Optional[List[str]], Field(description="Extra arguments to pass to IDA")] = None,
    ) -> dict:
        return lifecycle.open_in_ida(file_path, extra_args=extra_args)

    @server.tool(description="Close the target IDA instance. Warning: This terminates the process.")
    def close_ida(
        save: Annotated[bool, Field(description="Whether to save IDB file before closing")] = True,
        port: _PORT_ANNOTATION = None,
        timeout: _TIMEOUT_ANNOTATION = None,
    ) -> dict:
        return lifecycle.close_ida(save=save, port=port, timeout=timeout)

    @server.tool(description="Request shutdown of the standalone gateway. Refuses while instances are registered unless force=true.")
    def shutdown_gateway(
        force: Annotated[bool, Field(description="Allow shutdown even if instances are still registered")] = False,
        timeout: _TIMEOUT_ANNOTATION = None,
    ) -> dict:
        return lifecycle.shutdown_gateway(force=force, timeout=timeout)
