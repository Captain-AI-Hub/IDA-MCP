"""RPC decorators and the tool registry."""
from __future__ import annotations

from dataclasses import dataclass
import functools
import inspect
import json
from typing import Any, Callable, Dict, get_type_hints


@dataclass
class ToolSpec:
    name: str
    fn: Callable
    description: str
    execution_mode: str
    module_name: str


_tools: Dict[str, Callable] = {}
_tool_specs: Dict[str, ToolSpec] = {}


def _tool_description(fn: Callable) -> str:
    doc = inspect.getdoc(fn) or ""
    return doc.split("\n")[0].strip() if doc else fn.__name__


def _execution_mode(fn: Callable) -> str:
    return str(getattr(fn, "_ida_exec_mode", "direct"))


def _build_tool_spec(fn: Callable) -> ToolSpec:
    return ToolSpec(
        name=fn.__name__,
        fn=fn,
        description=_tool_description(fn),
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


def get_tools() -> Dict[str, Callable]:
    return dict(_tools)


def get_tool_specs() -> Dict[str, ToolSpec]:
    return dict(_tool_specs)


def text_result_tool(fn: Callable) -> Callable:
    """Wrap a tool function so FastMCP emits a single text content block.

    FastMCP mirrors dict/list return values into ``structuredContent`` in
    addition to the JSON text content, which makes chat clients render (and
    tokenize) every result twice. Returning a plain string keeps exactly one
    copy on the wire; structured data is sent as compact JSON text.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        result = fn(*args, **kwargs)
        if isinstance(result, str):
            return result
        return json.dumps(result, ensure_ascii=False, default=str, separators=(",", ":"))

    # Drop the return annotation so FastMCP does not generate an output schema;
    # with an output schema it would mirror the payload into structuredContent.
    signature = inspect.signature(fn)
    wrapper.__signature__ = signature.replace(return_annotation=inspect.Signature.empty)  # type: ignore[attr-defined]
    annotations = dict(getattr(fn, "__annotations__", {}))
    annotations.pop("return", None)
    wrapper.__annotations__ = annotations
    return wrapper


def reset_registry() -> None:
    """Clear all registered tools and specs.

    Intended exclusively for use in test teardown.
    """
    _tools.clear()
    _tool_specs.clear()
