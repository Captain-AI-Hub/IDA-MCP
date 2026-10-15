"""Standalone MCP server over stdio (the only transport).

Process model:

    MCP client ──stdio──▶ this process
                 │
                 ├─ JSON registry discovery (<state>/instances.json)
                 └─ direct JSON-RPC bridge calls into the selected IDA
                    process (GUI plugin instance or headless idalib worker)

All backend tools from the ``api_*`` catalog are forwarded to the currently
selected instance; lifecycle tools manage multiple instances
(open_database / list_databases / save_database / close_database), and
``ida_python_reference`` searches the official IDAPython documentation of the
attached IDA runtime.

fastmcp is imported lazily so instance CLI commands stay fast and never pay
the MCP stack import cost.
"""

from __future__ import annotations

import functools
import inspect
import json
import threading
from typing import Annotated, Any, Dict, List, Optional, get_args, get_origin, get_type_hints

from . import bridge_client, instances, lifecycle
from .api_loader import ensure_api_modules_loaded
from .config import get_request_timeout
from .errors import error_payload
from .idapython_docs import DocsIndex, format_entries
from .rpc import ToolSpec, get_tool_specs, text_result_tool

__version__ = "0.9.2"

# Backend tools replaced by standalone management tools.
_MANAGED_TOOL_NAMES = {"check_connection", "list_instances", "close_ida"}

_LOCK = threading.RLock()
_SELECTED: Optional[Dict[str, Any]] = None
_DOCS_INDEX: Optional[DocsIndex] = None
_DOCS_INSTANCE_ID: Optional[str] = None


def _field(description: str):
    try:
        from pydantic import Field

        return Field(description=description)
    except ImportError:  # pragma: no cover
        return None


# ============================================================================
# Instance selection and forwarding
# ============================================================================


def _select_entry(entry: Optional[Dict[str, Any]]) -> None:
    global _SELECTED, _DOCS_INDEX, _DOCS_INSTANCE_ID
    with _LOCK:
        _SELECTED = entry
        if entry is None or entry.get("instance_id") != _DOCS_INSTANCE_ID:
            _DOCS_INDEX = None
            _DOCS_INSTANCE_ID = None


def set_selected(instance_id: Optional[str]) -> Optional[Dict[str, Any]]:
    entry = None
    if instance_id:
        entry = instances.find_by_id(str(instance_id))
    else:
        # Auto-select the most recently started live instance.
        live = [e for e in instances.list_live_instances() if bridge_client.is_alive(e)]
        entry = live[-1] if live else None
    if entry is None or not bridge_client.is_alive(entry):
        return None
    _select_entry(entry)
    return entry


def resolve_instance(instance_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Resolve the target instance for a call; auto-select when omitted."""
    with _LOCK:
        selected = _SELECTED
    if instance_id:
        entry = instances.find_by_id(str(instance_id))
        if entry is None or not bridge_client.is_alive(entry):
            return None
        return entry
    if selected is not None and bridge_client.is_alive(selected):
        return selected
    # Auto-select the most recently started live instance.
    live = [e for e in instances.list_live_instances() if bridge_client.is_alive(e)]
    if live:
        entry = live[-1]
        _select_entry(entry)
        return entry
    return None


def forward(
    tool: str,
    params: Optional[Dict[str, Any]] = None,
    instance_id: Optional[str] = None,
    timeout: Optional[float] = None,
) -> Any:
    """Call one backend tool on the resolved instance."""
    entry = resolve_instance(instance_id)
    if entry is None:
        return error_payload(
            "no_instance",
            "No live IDA instance available. Call open_database() first or select an instance via list_databases().",
        )
    try:
        return bridge_client.call_tool(entry, tool, params or {}, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - tool boundary
        return bridge_client.describe_error(exc)


# ============================================================================
# Forwarded catalog registration (signature-preserving wrappers)
# ============================================================================


def _forward_parameter(name: str, annotation: Any, description: str) -> inspect.Parameter:
    return inspect.Parameter(
        name=name,
        kind=inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation=Annotated[annotation, _field(description)],
    )


def _build_forward_signature(spec: ToolSpec) -> inspect.Signature:
    source_signature = inspect.signature(spec.fn)
    params = list(source_signature.parameters.values())
    params.append(_forward_parameter("instance_id", Optional[str], "Instance id override"))
    params.append(_forward_parameter("timeout", Optional[int], "Timeout in seconds"))
    return source_signature.replace(parameters=params)


def _is_list_return(annotation: Any) -> bool:
    while get_origin(annotation) is Annotated:
        args = get_args(annotation)
        if not args:
            break
        annotation = args[0]
    return annotation is list or get_origin(annotation) is list


def _normalize_forwarded_result(spec: ToolSpec, result: Any) -> Any:
    return_annotation = get_type_hints(spec.fn, include_extras=True).get("return")
    if not _is_list_return(return_annotation):
        return result
    if isinstance(result, list):
        return result
    if (
        isinstance(result, dict)
        and set(result.keys()) == {"result"}
        and isinstance(result.get("result"), list)
    ):
        return result["result"]
    if result is None:
        return []
    return [result]


def _build_forward_wrapper(spec: ToolSpec) -> Any:
    source_signature = inspect.signature(spec.fn)
    source_param_names = tuple(source_signature.parameters.keys())
    source_hints = get_type_hints(spec.fn, include_extras=True)

    @functools.wraps(spec.fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        instance_id = kwargs.pop("instance_id", None)
        timeout = kwargs.pop("timeout", None)
        bound = source_signature.bind_partial(*args, **kwargs)
        params = {
            name: bound.arguments[name]
            for name in source_param_names
            if name in bound.arguments
        }
        result = forward(spec.name, params, instance_id, timeout=timeout)
        if isinstance(result, dict) and "error" in result:
            return result
        return _normalize_forwarded_result(spec, result)

    wrapper.__signature__ = _build_forward_signature(spec)  # type: ignore[attr-defined]
    wrapper.__annotations__ = dict(source_hints)
    wrapper.__annotations__["instance_id"] = Annotated[
        Optional[str], _field("Instance id override")
    ]
    wrapper.__annotations__["timeout"] = Annotated[
        Optional[int], _field("Timeout in seconds")
    ]
    return wrapper


# ============================================================================
# Server construction
# ============================================================================


def build_server() -> "Any":
    """Compose the standalone FastMCP server with all tools."""
    from fastmcp import FastMCP

    ensure_api_modules_loaded()
    server = FastMCP(
        name="IDA-MCP",
        version=__version__,
        instructions=(
            "IDA Pro 逆向分析 MCP。先 open_database(path) 打开/附加数据库"
            "（无头 idalib worker 会自动创建并分析 .i64），list_databases() 查看多实例，"
            "其余工具作用于当前选中实例，可用 instance_id 参数覆盖。"
            "ida_python_reference(query) 查询官方 IDAPython API 文档。"
        ),
    )

    _register_management_tools(server)

    for spec in sorted(get_tool_specs().values(), key=lambda item: item.name):
        if spec.name in _MANAGED_TOOL_NAMES:
            continue
        wrapper = _build_forward_wrapper(spec)
        server.tool(description=spec.description)(text_result_tool(wrapper))

    return server


def _register_management_tools(server: "Any") -> None:
    def check_connection() -> dict:
        """Check whether an IDA instance is attached."""
        entry = resolve_instance()
        if entry is None:
            return {"ok": False, "instances": 0}
        try:
            meta = bridge_client.get_meta(entry)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        return {
            "ok": True,
            "instance_id": entry.get("instance_id"),
            "pid": entry.get("pid"),
            "headless": bool(entry.get("headless")),
            "input_file": meta.get("input_file"),
            "database_path": meta.get("database_path"),
            "ida_version": meta.get("ida_version"),
        }

    server.tool(
        description="Health check. Returns {ok, instance_id, pid, input_file, ...} for the current IDA instance."
    )(text_result_tool(check_connection))

    def list_databases() -> List[dict]:
        """List live IDA instances (GUI and headless workers)."""
        current = resolve_instance()
        current_id = current.get("instance_id") if current else None
        result = []
        for entry in instances.list_live_instances():
            result.append(
                {
                    "instance_id": entry.get("instance_id"),
                    "pid": entry.get("pid"),
                    "headless": bool(entry.get("headless")),
                    "input_file": entry.get("input_file"),
                    "database_path": entry.get("database_path"),
                    "started_at": entry.get("started_at"),
                    "current": entry.get("instance_id") == current_id,
                }
            )
        return result

    server.tool(
        description="List all live IDA databases/instances ({instance_id, pid, headless, input_file, current})."
    )(text_result_tool(list_databases))

    def select_database(
        instance_id: Annotated[
            Optional[str], _field("Instance id from list_databases; omit to auto-select")
        ] = None,
    ) -> dict:
        """Select the default target instance for subsequent tool calls."""
        entry = set_selected(instance_id)
        if entry is None:
            return error_payload(
                "instance_not_found",
                "Instance not found or unreachable. Use list_databases() to see live instances.",
                instance_id=instance_id,
            )
        return {"selected_instance_id": entry.get("instance_id")}

    server.tool(
        description="Choose the default IDA instance for subsequent calls. Returns {selected_instance_id} or {error}."
    )(text_result_tool(select_database))

    def open_database(
        path: Annotated[
            str,
            _field(
                "Path to a local executable or .i64/.idb database. A live instance "
                "with this file is attached when present; otherwise a headless "
                "idalib worker opens/creates/analyzes it."
            ),
        ],
        set_current: Annotated[
            bool, _field("Make this database the default target (default true)")
        ] = True,
        headless: Annotated[
            str,
            _field(
                '"auto" (default: attach, else headless worker), "headless"/"true" '
                '(force idalib worker), "gui"/"false" (launch the IDA GUI)'
            ),
        ] = "auto",
        wait_for_analysis: Annotated[
            bool, _field("Wait for IDA auto-analysis to finish (default true)")
        ] = True,
        timeout: Annotated[
            int, _field("Open/analysis wait timeout in seconds (default 300)")
        ] = 300,
        extra_args: Annotated[
            Optional[List[str]], _field("Extra IDA CLI args for GUI launches")
        ] = None,
    ) -> dict:
        """Open (or attach to) a binary executable, firmware image, or existing
        .i64/.idb IDA database. Headless idalib workers create and analyze the
        .i64 for raw binaries; GUI instances attach if the file is already open
        or launch when headless="gui". Returns the instance record."""
        return lifecycle.open_database(
            path,
            set_current=set_current,
            headless=headless,
            wait_for_analysis=wait_for_analysis,
            timeout=timeout,
            extra_args=extra_args,
            select_callback=lambda instance_id: set_selected(instance_id),
        )

    server.tool(
        description="Open a binary or .i64 database in IDA: attach to a live instance, or spawn a headless idalib worker that creates/analyzes the .i64. Call this first."
    )(text_result_tool(open_database))

    def save_database(
        instance_id: Annotated[
            Optional[str], _field("Instance id; defaults to the current target")
        ] = None,
        timeout: Annotated[Optional[int], _field("Timeout in seconds")] = None,
    ) -> dict:
        """Save the IDA database (.i64) so renames, comments, types and patches persist."""
        entry = resolve_instance(instance_id)
        if entry is None:
            return error_payload("no_instance", "No live IDA instance selected.")
        try:
            return lifecycle.save_database(entry)
        except Exception as exc:  # noqa: BLE001
            return bridge_client.describe_error(exc)

    server.tool(
        description="Save the current (or specified) IDA database to disk (.i64)."
    )(text_result_tool(save_database))

    def close_database(
        instance_id: Annotated[
            Optional[str], _field("Instance id; defaults to the current target")
        ] = None,
        terminate: Annotated[
            bool,
            _field(
                "Also close GUI instances; headless workers are always shut down "
                "(saved first) when their last user detaches"
            ),
        ] = False,
        save: Annotated[bool, _field("Save the database before closing")] = True,
    ) -> dict:
        """Release an IDA database. Headless workers shut down (saving by
        default); GUI instances stay open unless terminate=true."""
        entry = resolve_instance(instance_id)
        if entry is None:
            return error_payload("no_instance", "No live IDA instance selected.")
        result = lifecycle.close_database(entry, terminate=terminate, save=save)
        if instance_id is None and result.get("status") in {"closed", "detached"}:
            _select_entry(None)
        return result

    server.tool(
        description="Release/detach an IDA database instance. Headless workers are shut down (saved by default); GUI stays open unless terminate=true."
    )(text_result_tool(close_database))

    def ida_python_reference(
        query: Annotated[
            str,
            _field(
                "Class, function, or concept to look up in the official IDAPython "
                "docs of the attached IDA runtime, e.g. 'decompile', 'xrefs to', "
                "'ida_funcs', 'rename local variable'. Use 'modules' to list modules."
            ),
        ],
        module: Annotated[
            Optional[str], _field("Restrict the search to one module, e.g. ida_funcs")
        ] = None,
        limit: Annotated[
            int, _field("Maximum number of entries returned (default 20)")
        ] = 20,
    ) -> str:
        """Search the official IDAPython API reference (built live from the
        attached IDA's ida_* modules). Returns signatures and docstrings for
        use with py_eval / IDAPython scripting."""
        entry = resolve_instance()
        if entry is None:
            return json.dumps(
                error_payload(
                    "no_instance",
                    "Open a database first; the IDAPython reference is built from the attached IDA runtime.",
                ),
                ensure_ascii=False,
            )
        index = _get_docs_index(entry)
        if query.strip().lower() in {"modules", "list modules", "module list"}:
            return json.dumps(index.module_summary(), ensure_ascii=False, indent=2)
        entries = index.search(query, module=module, limit=max(1, min(limit, 50)))
        return format_entries(entries, query)

    server.tool(
        description="Search the official IDAPython API documentation (from the attached IDA runtime). Returns signatures + docstrings; pass 'modules' as query to list modules."
    )(text_result_tool(ida_python_reference))


def _get_docs_index(entry: Dict[str, Any]) -> DocsIndex:
    global _DOCS_INDEX, _DOCS_INSTANCE_ID
    with _LOCK:
        if _DOCS_INDEX is not None and _DOCS_INSTANCE_ID == entry.get("instance_id"):
            return _DOCS_INDEX
        index = DocsIndex()
        index.build(
            fetch_modules=lambda: bridge_client.docs_modules(entry, timeout=30.0),
            fetch_snapshot=lambda name: bridge_client.docs_snapshot(entry, name, timeout=60.0),
        )
        _DOCS_INDEX = index
        _DOCS_INSTANCE_ID = entry.get("instance_id")
        return index


# ============================================================================
# Serving: stdio only
# ============================================================================


def serve_stdio() -> None:
    """Serve MCP on stdin/stdout until the peer closes its input."""
    import atexit

    server = build_server()
    atexit.register(lifecycle.shutdown_managed)
    try:
        server.run(transport="stdio", show_banner=False)
    except TypeError:  # pragma: no cover - older fastmcp without show_banner
        server.run(transport="stdio")
