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


def is_unsafe(fn: Callable) -> bool:
    spec = _tool_specs.get(fn.__name__)
    if spec is not None and spec.fn is fn:
        return spec.unsafe
    return _unsafe_flag(fn)


def reset_registry() -> None:
    """Clear all registered tools, specs, and resources.

    Intended exclusively for use in test teardown.
    """
    _tools.clear()
    _tool_specs.clear()
    _resources.clear()


def ensure_api_modules_loaded() -> None:
    """Import all api_* modules to populate the tool and resource registries.

    This triggers the @tool and @resource decorator side-effects that
    populate ``_tools``, ``_tool_specs``, and ``_resources``.  It is safe
    to call multiple times (subsequent calls are no-ops).
    """
    from . import api_analysis  # noqa: F401
    from . import api_core  # noqa: F401
    from . import api_debug  # noqa: F401
    from . import api_lifecycle  # noqa: F401
    from . import api_memory  # noqa: F401
    from . import api_modeling  # noqa: F401
    from . import api_modify  # noqa: F401
    from . import api_python  # noqa: F401
    from . import api_resources  # noqa: F401
    from . import api_stack  # noqa: F401
    from . import api_types  # noqa: F401
