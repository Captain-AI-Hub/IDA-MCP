#!/usr/bin/env python
"""IDA-MCP command-line interface.

Default action serves MCP over stdio (the only transport).::

    idamcp-hub            # serve MCP over stdio

Instance operations::

    idamcp instances list
    idamcp open <path> [--gui] [--no-wait]
    idamcp close [--id ID] [--terminate] [--no-save]
    idamcp save [--id ID]
    idamcp tool call NAME [--params JSON] [--id ID]
    idamcp reference "query" [--module ida_funcs]
    idamcp config show
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Optional, Sequence

_repo_root = str(pathlib.Path(__file__).resolve().parents[1])
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

_script_dir = str(pathlib.Path(__file__).resolve().parent)
sys.path = [p for p in sys.path if p != _script_dir]


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3


def _dump_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _resolve_entry(instance_id: Optional[str]):
    """Pick a live instance: by id, else latest started."""
    from . import bridge_client, instances

    if instance_id:
        entry = instances.find_by_id(instance_id)
        if entry is None or not bridge_client.is_alive(entry):
            print(f"Error: instance {instance_id} not found or unreachable.")
            return None
        return entry
    live = [e for e in instances.list_live_instances() if bridge_client.is_alive(e)]
    if not live:
        print("Error: no live IDA instance. Run `idamcp open <path>` first.")
        return None
    return live[-1]


# ============================================================================
# Serve commands
# ============================================================================


def _cmd_stdio(_args: argparse.Namespace) -> int:
    from . import mcp_server

    mcp_server.serve_stdio()
    return EXIT_OK


# ============================================================================
# Instance commands
# ============================================================================


def _cmd_instances_list(args: argparse.Namespace) -> int:
    from . import bridge_client, instances

    entries = [
        e for e in instances.list_live_instances() if bridge_client.is_alive(e)
    ]
    if args.json:
        _dump_json(entries)
        return EXIT_OK
    if not entries:
        print("No live IDA instances.")
        return EXIT_OK
    for entry in entries:
        headless = "headless" if entry.get("headless") else "gui"
        input_file = entry.get("input_file") or "<unknown>"
        print(
            f"{entry.get('instance_id')}  pid={entry.get('pid')} "
            f"port={entry.get('port')} [{headless}] {input_file}"
        )
    return EXIT_OK


def _cmd_open(args: argparse.Namespace) -> int:
    from . import lifecycle

    headless = "gui" if args.gui else "auto"
    result = lifecycle.open_database(
        args.file_path,
        set_current=False,
        headless=headless,
        wait_for_analysis=not args.no_wait,
        timeout=args.timeout,
    )
    if "error" in result:
        print(f"Error: {result['error']}")
        return EXIT_ERROR
    instance = result.get("instance") or {}
    print(
        f"{result.get('status')} ({result.get('mode', 'attached')}): "
        f"instance {instance.get('instance_id')} pid={instance.get('pid')} "
        f"port={instance.get('port')}"
    )
    print(f"input: {instance.get('input_file')}")
    print(f"database: {instance.get('database_path')}")
    if result.get("worker_python"):
        print(f"worker python: {result['worker_python']}")
    return EXIT_OK


def _cmd_close(args: argparse.Namespace) -> int:
    from . import lifecycle

    entry = _resolve_entry(args.id)
    if entry is None:
        return EXIT_UNAVAILABLE
    result = lifecycle.close_database(
        entry, terminate=args.terminate, save=not args.no_save
    )
    _dump_json(result)
    return EXIT_ERROR if result.get("status") == "error" else EXIT_OK


def _cmd_save(args: argparse.Namespace) -> int:
    from . import lifecycle

    entry = _resolve_entry(args.id)
    if entry is None:
        return EXIT_UNAVAILABLE
    _dump_json(lifecycle.save_database(entry))
    return EXIT_OK


def _cmd_tool_call(args: argparse.Namespace) -> int:
    from . import bridge_client

    entry = _resolve_entry(args.id)
    if entry is None:
        return EXIT_UNAVAILABLE
    try:
        params = json.loads(args.params) if args.params else {}
        if not isinstance(params, dict):
            raise ValueError("--params must decode to a JSON object")
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON for --params: {exc}")
        return EXIT_USAGE

    try:
        result = bridge_client.call_tool(entry, args.tool_name, params, timeout=args.timeout)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _dump_json(bridge_client.describe_error(exc))
        return EXIT_ERROR
    _dump_json(result)
    return EXIT_OK


def _cmd_reference(args: argparse.Namespace) -> int:
    from .idapython_docs import DocsIndex, format_entries

    entry = _resolve_entry(args.id)
    if entry is None:
        return EXIT_UNAVAILABLE

    def fetch_modules():
        from . import bridge_client

        return bridge_client.docs_modules(entry)

    def fetch_snapshot(name: str):
        from . import bridge_client

        return bridge_client.docs_snapshot(entry, name)

    index = DocsIndex()
    print(f"Indexing IDAPython modules from instance {entry.get('instance_id')}...", file=sys.stderr)
    index.build(fetch_modules, fetch_snapshot)
    print(f"Indexed {index.size} entries.", file=sys.stderr)
    if args.query.strip().lower() in {"modules", "list modules", "module list"}:
        _dump_json(index.module_summary())
        return EXIT_OK
    print(format_entries(index.search(args.query, module=args.module), args.query))
    return EXIT_OK


def _cmd_config_show(_args: argparse.Namespace) -> int:
    from . import config

    _dump_json(config.load_config(reload=True))
    return EXIT_OK


# ============================================================================
# Parser
# ============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idamcp-hub",
        description="IDA-MCP: stdio MCP server + instance CLI",
    )
    subparsers = parser.add_subparsers(dest="command")

    stdio = subparsers.add_parser(
        "stdio", help="Serve MCP over stdin/stdout (default command)"
    )
    stdio.set_defaults(handler=_cmd_stdio)

    instances_parser = subparsers.add_parser("instances", help="Inspect live IDA instances")
    instances_sub = instances_parser.add_subparsers(dest="instances_command")
    instances_list = instances_sub.add_parser("list", help="List live IDA instances")
    instances_list.add_argument("--json", action="store_true", help="Print JSON output")
    instances_list.set_defaults(handler=_cmd_instances_list)

    open_parser = subparsers.add_parser(
        "open", help="Open/attach a binary or .i64 (headless idalib worker by default)"
    )
    open_parser.add_argument("file_path", help="Path to the executable or IDB")
    open_parser.add_argument(
        "--gui", action="store_true",
        help="Launch the IDA GUI instead of a headless worker",
    )
    open_parser.add_argument(
        "--no-wait", action="store_true", help="Do not wait for auto-analysis"
    )
    open_parser.add_argument(
        "--timeout", type=int, default=300, help="Open timeout in seconds (default 300)"
    )
    open_parser.set_defaults(handler=_cmd_open)

    close_parser = subparsers.add_parser("close", help="Close/detach an IDA instance")
    close_parser.add_argument("--id", default=None, help="Instance id (default: latest)")
    close_parser.add_argument(
        "--terminate", action="store_true", help="Also close GUI instances"
    )
    close_parser.add_argument(
        "--no-save", action="store_true", help="Do not save the database before closing"
    )
    close_parser.set_defaults(handler=_cmd_close)

    save_parser = subparsers.add_parser("save", help="Save an instance database")
    save_parser.add_argument("--id", default=None, help="Instance id (default: latest)")
    save_parser.set_defaults(handler=_cmd_save)

    tool_parser = subparsers.add_parser("tool", help="Direct tool invocation")
    tool_sub = tool_parser.add_subparsers(dest="tool_command")
    tool_call = tool_sub.add_parser("call", help="Call one backend tool")
    tool_call.add_argument("tool_name", help="Tool name")
    tool_call.add_argument("--id", default=None, help="Instance id (default: latest)")
    tool_call.add_argument("--timeout", type=int, default=None, help="Timeout in seconds")
    tool_call.add_argument("--params", default="{}", help="Tool params as a JSON object")
    tool_call.set_defaults(handler=_cmd_tool_call)

    reference = subparsers.add_parser(
        "reference", help="Search the official IDAPython documentation"
    )
    reference.add_argument("query", help="Class, function, or concept (or 'modules')")
    reference.add_argument("--module", default=None, help="Restrict to one module")
    reference.add_argument("--id", default=None, help="Instance id (default: latest)")
    reference.set_defaults(handler=_cmd_reference)

    config_parser = subparsers.add_parser("config", help="Inspect configuration")
    config_sub = config_parser.add_subparsers(dest="config_command")
    config_show = config_sub.add_parser("show", help="Print the effective configuration")
    config_show.set_defaults(handler=_cmd_config_show)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        # No arguments: serve MCP over stdio.
        arguments = ["stdio"]
    parser = build_parser()
    args = parser.parse_args(arguments)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return EXIT_USAGE
    try:
        return int(handler(args))
    except KeyboardInterrupt:
        print("Interrupted.")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
