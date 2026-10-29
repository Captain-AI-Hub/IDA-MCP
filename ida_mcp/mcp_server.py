"""Standalone MCP server over stdio (the only transport).

Process model:

    MCP client ──stdio──▶ this process
                 │
                 ├─ JSON registry discovery (<state>/instances.json)
                 └─ direct JSON-RPC bridge calls into the selected IDA
                    process (a headless idalib worker)

All backend tools from the ``api_*`` catalog are forwarded per call: an
explicit ``instance_id`` argument always wins; when omitted, the sole live
instance is the implicit target (there is no mutable default selection, so
concurrent agents can never re-route each other's calls; with several live
instances an omitted id is a loud error listing them). Lifecycle tools manage
multiple instances (open_database / list_databases / save_database /
close_database), and ``ida_python_reference`` searches the official IDAPython
documentation of the attached IDA runtime.

fastmcp is imported lazily so instance CLI commands stay fast and never pay
the MCP stack import cost.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import threading
import time
from typing import Annotated, Any, Dict, List, Optional, get_args, get_origin, get_type_hints

from . import bridge_client, instances, lifecycle
from .api_loader import ensure_api_modules_loaded
from .config import get_request_timeout
from .errors import error_payload
from .idapython_docs import DocsIndex, format_entries
from .rpc import ToolSpec, get_tool_specs, text_result_tool

__version__ = "1.0.0"

# Backend tools replaced by standalone management tools.
_MANAGED_TOOL_NAMES = {"check_connection", "list_instances"}

_LOCK = threading.RLock()
_LEASED: set = set()  # instance ids this server process holds a lease on
_DOCS_INDEX: Optional[DocsIndex] = None
_DOCS_INSTANCE_ID: Optional[str] = None

_INSTANCE_ID_HELP = (
    "REQUIRED whenever more than one database is open (from open_database's "
    "result or list_databases()); optional only while exactly one instance "
    "is live."
)


def _field(description: str):
    try:
        from pydantic import Field

        return Field(description=description)
    except ImportError:  # pragma: no cover
        return None


# ============================================================================
# Instance resolution and forwarding
# ============================================================================


def resolve_instance(instance_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Resolve the target instance for a call.

    An explicit ``instance_id`` always wins (and never falls through to
    another database when dead). Without one, the sole live instance is the
    implicit target — there is no mutable default selection, so concurrent
    agents cannot re-route each other's calls. With several live instances an
    omitted id must fail loudly (see :func:`_routing_error`).
    """
    if instance_id:
        entry = instances.find_by_id(str(instance_id))
        if entry is None or not bridge_client.is_alive(entry):
            return None
        _lease(entry)
        return entry
    live = [e for e in instances.list_live_instances() if bridge_client.is_alive(e)]
    if len(live) == 1:
        _lease(live[0])
        return live[0]
    return None


def _routing_error(instance_id: Optional[str]) -> Dict[str, Any]:
    """Explain why resolve_instance failed, with an actionable recovery hint."""
    if instance_id:
        entry = instances.find_by_id(str(instance_id))
        if entry is None:
            return error_payload(
                "instance_not_found",
                f"Instance {instance_id} is not in the registry. "
                "Use list_databases() to see live instances.",
            )
        return error_payload(
            "instance_gone",
            f"Instance {instance_id} ({entry.get('input_file') or 'unknown file'}) "
            "is no longer running. Use list_databases() to see live instances.",
        )
    live = [e for e in instances.list_live_instances() if bridge_client.is_alive(e)]
    if not live:
        return error_payload(
            "no_instance",
            "No live IDA instance available. Call open_database() first.",
        )
    listing = "\n".join(
        f"  {e.get('instance_id')}  {e.get('input_file') or e.get('database_path') or '<unknown>'}"
        for e in live
    )
    return error_payload(
        "instance_ambiguous",
        "Multiple IDA instances are live; retry THIS call with instance_id "
        "(from open_database's result or list_databases()):\n" + listing,
    )


def _lease(entry: Optional[Dict[str, Any]]) -> None:
    """Record cross-process usage so close_database knows who is active."""
    instance_id = str((entry or {}).get("instance_id") or "")
    if not instance_id:
        return
    with _LOCK:
        if instance_id in _LEASED:
            return
        _LEASED.add(instance_id)
    try:
        instances.lease_add(instance_id, os.getpid())
    except Exception:  # noqa: BLE001 - leases are best effort
        pass


def forward(
    tool: str,
    params: Optional[Dict[str, Any]] = None,
    instance_id: Optional[str] = None,
    timeout: Optional[float] = None,
) -> Any:
    """Call one backend tool on the resolved instance.

    Calls that carry a timeout get a server-assigned operation_id: when the
    call times out on this side, the in-flight execution is interrupted on
    the bridge instead of pinning the worker's thread forever.
    """
    entry = resolve_instance(instance_id)
    if entry is None:
        return _routing_error(instance_id)
    operation_id: Optional[str] = None
    if timeout is not None:
        operation_id = f"{tool}-{os.getpid()}-{threading.get_ident()}-{time.monotonic_ns()}"
    try:
        return bridge_client.call_tool(
            entry,
            tool,
            params or {},
            timeout=timeout,
            operation_id=operation_id,
        )
    except Exception as exc:  # noqa: BLE001 - tool boundary
        described = bridge_client.describe_error(exc)
        if (
            operation_id is not None
            and described.get("error", {}).get("code") == "timeout"
        ):
            # The HTTP deadline fired here; the code may still be running in
            # the worker. Ask the bridge to interrupt it so the thread
            # unwinds, then surface the cancellation, not just the timeout.
            cancelled = False
            try:
                cancelled = bridge_client.cancel_operation(entry, operation_id)
            except Exception:  # noqa: BLE001 - cancellation is best effort
                cancelled = False
            if cancelled:
                return error_payload(
                    "operation_cancelled",
                    f"{tool} exceeded its {timeout}s timeout; the in-flight "
                    "execution was interrupted on the instance. Retry with a "
                    "larger timeout parameter or shorter code.",
                )
        return described


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
    params.append(_forward_parameter("instance_id", Optional[str], _INSTANCE_ID_HELP))
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
        Optional[str], _field(_INSTANCE_ID_HELP)
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
            "（无头 idalib worker 会自动创建并分析 .i64）。instance_id 路由规则："
            "多个实例同时打开时，每次工具调用都必须传 instance_id（来自 "
            "open_database 的返回值或 list_databases()）；省略报 "
            "instance_ambiguous 错误时，重试同一调用并补上 instance_id 即可。"
            "只有一个实例时可省略 instance_id。"
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
        description="Health check. Returns {ok, instance_id, pid, input_file, ...} for the resolved IDA instance."
    )(text_result_tool(check_connection))

    def list_databases() -> List[dict]:
        """List live idalib worker instances."""
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
                }
            )
        return result

    server.tool(
        description="List all live IDA databases/instances ({instance_id, pid, headless, input_file}); pass one as instance_id on every tool call while several are live."
    )(text_result_tool(list_databases))

    def open_database(
        path: Annotated[
            str,
            _field(
                "Path to a local executable or .i64/.idb database. A live worker "
                "with this file is attached when present; otherwise a headless "
                "idalib worker opens/creates/analyzes it."
            ),
        ],
        wait_for_analysis: Annotated[
            bool, _field("Wait for IDA auto-analysis to finish (default true)")
        ] = True,
        timeout: Annotated[
            int, _field("Open/analysis wait timeout in seconds (default 300)")
        ] = 300,
    ) -> dict:
        """Open (or attach to) a binary executable, firmware image, or existing
        .i64/.idb IDA database in a headless idalib worker (the .i64 is created
        and analyzed for raw binaries). Returns the instance record — cite its
        instance_id on later tool calls whenever several databases are open."""
        return lifecycle.open_database(
            path,
            wait_for_analysis=wait_for_analysis,
            timeout=timeout,
        )

    server.tool(
        description="Open a binary or .i64 database in a headless idalib worker (creates/analyzes the .i64). Call this first. Record the returned instance.instance_id — every subsequent tool call must carry it while multiple databases are open."
    )(text_result_tool(open_database))

    def save_database(
        instance_id: Annotated[
            Optional[str], _field(_INSTANCE_ID_HELP)
        ] = None,
        timeout: Annotated[Optional[int], _field("Timeout in seconds")] = None,
    ) -> dict:
        """Save the IDA database (.i64) so renames, comments, types and patches persist."""
        entry = resolve_instance(instance_id)
        if entry is None:
            return _routing_error(instance_id)
        try:
            return lifecycle.save_database(entry)
        except Exception as exc:  # noqa: BLE001
            return bridge_client.describe_error(exc)

    server.tool(
        description="Save the current (or specified) IDA database to disk (.i64)."
    )(text_result_tool(save_database))

    def close_database(
        instance_id: Annotated[
            Optional[str], _field(_INSTANCE_ID_HELP)
        ] = None,
        terminate: Annotated[
            bool,
            _field(
                "Force shutdown even while other agents still hold leases on "
                "this worker"
            ),
        ] = False,
        save: Annotated[bool, _field("Save the database before closing")] = True,
    ) -> dict:
        """Release an IDA database worker. It is saved and shut down when its
        last user detaches; terminate=true forces an immediate shutdown."""
        entry = resolve_instance(instance_id)
        if entry is None:
            return _routing_error(instance_id)
        return lifecycle.close_database(entry, terminate=terminate, save=save)

    server.tool(
        description="Release an IDA database worker: saved and shut down when the last user detaches; terminate=true forces shutdown. Only close a database when its analysis is finished."
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
