"""RPC decorators and tool/resource registries."""
from __future__ import annotations

from dataclasses import dataclass
import inspect
from typing import Any, Callable, Dict, Optional, get_type_hints


@dataclass
class ToolSpec:
    name: str
    fn: Callable
    description: str
    unsafe: bool
    execution_mode: str
    module_name: str


_tools: Dict[str, Callable] = {}
_tool_specs: Dict[str, ToolSpec] = {}
_resources: Dict[str, Callable] = {}


def _tool_description(fn: Callable) -> str:
    doc = inspect.getdoc(fn) or ""
    return doc.split("\n")[0].strip() if doc else fn.__name__


def _execution_mode(fn: Callable) -> str:
    return str(getattr(fn, "_ida_exec_mode", "direct"))


def _unsafe_flag(fn: Callable) -> bool:
    return bool(getattr(fn, "_unsafe", False))


def _build_tool_spec(fn: Callable) -> ToolSpec:
    return ToolSpec(
        name=fn.__name__,
        fn=fn,
        description=_tool_description(fn),
        unsafe=_unsafe_flag(fn),
        execution_mode=_execution_mode(fn),
        module_name=str(getattr(fn, "__module__", "")),
    )


def _update_tool_spec(fn: Callable) -> None:
    if fn.__name__ in _tools:
        _tool_specs[fn.__name__] = _build_tool_spec(fn)


def tool(fn: Callable) -> Callable:
    """Register an MCP tool and capture its metadata."""
    _tools[fn.__name__] = fn
    _tool_specs[fn.__name__] = _build_tool_spec(fn)
    return fn


def resource(uri: str):
    """Register an MCP resource URI."""

    def decorator(fn: Callable) -> Callable:
        fn._resource_uri = uri  # type: ignore[attr-defined]
        _resources[uri] = fn
        return fn

    return decorator


def unsafe(fn: Callable) -> Callable:
    """Mark a tool as unsafe."""
    fn._unsafe = True  # type: ignore[attr-defined]
    _update_tool_spec(fn)
    return fn


def get_tools() -> Dict[str, Callable]:
    return dict(_tools)


def get_tool_specs() -> Dict[str, ToolSpec]:
    return dict(_tool_specs)


def get_resources() -> Dict[str, Callable]:
    return dict(_resources)


def get_tool_info(fn: Callable) -> dict:
    """Extract schema-friendly metadata for a registered tool."""
    sig = inspect.signature(fn)
    params = []

    try:
        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    for param_name, param in sig.parameters.items():
        param_info: dict[str, Any] = {"name": param_name}

        if param_name in hints:
            hint = hints[param_name]
            if hasattr(hint, "__metadata__"):
                param_info["type"] = str(hint.__origin__) if hasattr(hint, "__origin__") else str(hint)
                for meta in hint.__metadata__:
                    if isinstance(meta, str):
                        param_info["description"] = meta
                    elif hasattr(meta, "description"):
                        param_info["description"] = meta.description
            else:
                param_info["type"] = str(hint)

        if param.default is not inspect.Parameter.empty:
            param_info["default"] = param.default
            param_info["required"] = False
        else:
            param_info["required"] = True

        params.append(param_info)

    spec = _tool_specs.get(fn.__name__) or _build_tool_spec(fn)
    return {
        "name": spec.name,
        "description": spec.description,
        "parameters": params,
        "is_unsafe": spec.unsafe,
        "execution_mode": spec.execution_mode,
        "module_name": spec.module_name,
    }


def is_unsafe(fn: Callable) -> bool:
    spec = _tool_specs.get(fn.__name__)
    if spec is not None and spec.fn is fn:
        return spec.unsafe
    return _unsafe_flag(fn)


def clear_registry() -> None:
    _tools.clear()
    _tool_specs.clear()
    _resources.clear()
