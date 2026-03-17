#!/usr/bin/env python
"""IDA-MCP command-line helper."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from ida_mcp import control


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3


def _dump_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _exit_code_from_payload(payload: dict[str, Any], default: int = EXIT_OK) -> int:
    error = payload.get("error")
    if not isinstance(error, dict):
        return default
    code = error.get("code")
    if code in {
        "invalid_port",
        "invalid_json",
        "invalid_params",
    }:
        return EXIT_USAGE
    if code in {
        "gateway_unavailable",
        "fastmcp_missing",
        "instance_not_found",
        "no_instances",
        "resource_read_failed",
        "resource_list_failed",
    }:
        return EXIT_UNAVAILABLE
    return EXIT_ERROR


def _print_gateway_status(payload: dict[str, Any]) -> None:
    gateway = payload.get("gateway", {})
    proxy = payload.get("proxy", {})
    print(
        f"Gateway: {'running' if gateway.get('alive') else 'stopped'} "
        f"at {payload['coordinator']['host']}:{payload['coordinator']['port']}"
    )
    if gateway.get("log"):
        print(f"Gateway log: {gateway['log']}")
    if gateway.get("last_error"):
        print(f"Gateway error: {gateway['last_error']}")
    print(
        f"HTTP proxy: {'running' if proxy.get('alive') else 'stopped'} "
        f"at {payload['http_proxy']['host']}:{payload['http_proxy']['port']}{payload['http_proxy']['path']}"
    )
    if proxy.get("last_error"):
        print(f"HTTP proxy error: {proxy['last_error']}")
    print(f"Registered instances: {payload.get('count', 0)}")


def _print_instances(payload: dict[str, Any]) -> None:
    if not payload["gateway_alive"]:
        print("Gateway is not running.")
        return
    if not payload["instances"]:
        print("No registered IDA instances.")
        return
    for entry in payload["instances"]:
        port = entry.get("port")
        pid = entry.get("pid")
        input_file = entry.get("input_file") or "<unknown>"
        print(f"pid={pid} port={port} input={input_file}")


def _print_error(payload: dict[str, Any]) -> None:
    error = payload.get("error")
    if not isinstance(error, dict):
        print("Operation failed.")
        return
    print(f"Error [{error.get('code', 'unknown')}]: {error.get('message', 'unknown error')}")
    details = error.get("details")
    if details:
        print(json.dumps(details, indent=2, ensure_ascii=False, default=str))


def _print_select(payload: dict[str, Any]) -> None:
    instance = payload.get("instance") or {}
    print(f"Selected port: {payload['selected_port']}")
    if instance:
        print(f"PID: {instance.get('pid')}")
        print(f"Input: {instance.get('input_file') or '<unknown>'}")


def _print_data_payload(payload: dict[str, Any]) -> None:
    if "data" in payload:
        _dump_json(payload["data"])
        return
    _dump_json(payload)


def _cmd_gateway_start(args: argparse.Namespace) -> int:
    payload = control.ensure_gateway_running(startup_timeout=args.timeout)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        _print_gateway_status(payload)
    return _exit_code_from_payload(payload)


def _cmd_gateway_stop(args: argparse.Namespace) -> int:
    payload = control.shutdown_gateway(force=args.force, timeout=args.timeout)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        print(payload.get("message", "Gateway shutdown requested"))
    return _exit_code_from_payload(payload)


def _cmd_gateway_restart(args: argparse.Namespace) -> int:
    payload = control.restart_gateway(startup_timeout=args.timeout, force=args.force)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        _print_gateway_status(payload)
    return _exit_code_from_payload(payload)


def _cmd_gateway_status(args: argparse.Namespace) -> int:
    payload = control.gateway_status_payload()
    if args.json:
        _dump_json(payload)
    else:
        _print_gateway_status(payload)
    return EXIT_OK


def _cmd_ida_open(args: argparse.Namespace) -> int:
    payload = control.open_ida(args.file_path, extra_args=args.extra_arg or None)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        print(payload.get("message", "IDA launch requested"))
        if payload.get("requested_port") is not None:
            print(f"Requested port: {payload['requested_port']}")
    return _exit_code_from_payload(payload)


def _cmd_ida_close(args: argparse.Namespace) -> int:
    payload = control.close_ida(save=args.save, port=args.port, timeout=args.timeout)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        print(f"Close requested for port {payload['selected_port']}")
        _print_data_payload(payload)
    return _exit_code_from_payload(payload)


def _cmd_ida_list(args: argparse.Namespace) -> int:
    payload = control.list_ida_instances()
    if args.json:
        _dump_json(payload)
    else:
        _print_instances(payload)
    return EXIT_OK


def _cmd_ida_select(args: argparse.Namespace) -> int:
    payload = control.select_target_port(args.port)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        _print_select(payload)
    return _exit_code_from_payload(payload)


def _parse_params(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON for --params: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("--params must decode to a JSON object")
    return data


def _cmd_tool_call(args: argparse.Namespace) -> int:
    try:
        params = _parse_params(args.params)
    except ValueError as exc:
        payload = control.error_payload("invalid_json", str(exc))
        _dump_json(payload)
        return EXIT_USAGE

    payload = control.call_tool(args.tool_name, params=params, port=args.port, timeout=args.timeout)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        print(f"Tool: {args.tool_name}")
        print(f"Port: {payload['selected_port']}")
        _print_data_payload(payload)
    return _exit_code_from_payload(payload)


def _cmd_resource_read(args: argparse.Namespace) -> int:
    payload = control.read_resource(args.uri, port=args.port, timeout=args.timeout)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        print(f"Resource: {payload['uri']}")
        print(f"Port: {payload['selected_port']}")
        _print_data_payload(payload)
    return _exit_code_from_payload(payload)


def _cmd_resource_list(args: argparse.Namespace) -> int:
    payload = control.list_resources(port=args.port, timeout=args.timeout)
    if args.json or "error" in payload:
        _dump_json(payload)
    else:
        print(f"Port: {payload['selected_port']}")
        print(f"Total resources: {payload['total']}")
        _dump_json(
            {
                "resources": payload.get("resources", []),
                "templates": payload.get("templates", []),
            }
        )
    return _exit_code_from_payload(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IDA-MCP command-line helper")
    subparsers = parser.add_subparsers(dest="command")

    gateway_parser = subparsers.add_parser("gateway", help="Manage the standalone gateway")
    gateway_subparsers = gateway_parser.add_subparsers(dest="gateway_command")

    gateway_start = gateway_subparsers.add_parser("start", help="Start the standalone gateway")
    gateway_start.add_argument("--timeout", type=float, default=3.0, help="Startup timeout in seconds")
    gateway_start.add_argument("--json", action="store_true", help="Print JSON output")
    gateway_start.set_defaults(handler=_cmd_gateway_start)

    gateway_stop = gateway_subparsers.add_parser("stop", help="Stop the standalone gateway")
    gateway_stop.add_argument("--force", action="store_true", help="Force stop even if instances are registered")
    gateway_stop.add_argument("--timeout", type=float, default=None, help="Shutdown timeout in seconds")
    gateway_stop.add_argument("--json", action="store_true", help="Print JSON output")
    gateway_stop.set_defaults(handler=_cmd_gateway_stop)

    gateway_restart = gateway_subparsers.add_parser("restart", help="Restart the standalone gateway")
    gateway_restart.add_argument("--force", action="store_true", help="Force stop even if instances are registered")
    gateway_restart.add_argument("--timeout", type=float, default=3.0, help="Restart timeout in seconds")
    gateway_restart.add_argument("--json", action="store_true", help="Print JSON output")
    gateway_restart.set_defaults(handler=_cmd_gateway_restart)

    gateway_status = gateway_subparsers.add_parser("status", help="Show gateway status")
    gateway_status.add_argument("--json", action="store_true", help="Print JSON output")
    gateway_status.set_defaults(handler=_cmd_gateway_status)

    ida_parser = subparsers.add_parser("ida", help="Manage IDA instances")
    ida_subparsers = ida_parser.add_subparsers(dest="ida_command")

    ida_open = ida_subparsers.add_parser("open", help="Launch IDA with a file")
    ida_open.add_argument("file_path", help="Path to the file or IDB to open")
    ida_open.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="Extra argument to pass to IDA (repeatable)",
    )
    ida_open.add_argument("--json", action="store_true", help="Print JSON output")
    ida_open.set_defaults(handler=_cmd_ida_open)

    ida_close = ida_subparsers.add_parser("close", help="Close an IDA instance")
    ida_close.add_argument("--port", type=int, default=None, help="Target instance port")
    ida_close.add_argument("--timeout", type=int, default=None, help="Timeout in seconds")
    ida_close.add_argument("--save", dest="save", action="store_true", default=True, help="Save IDB before closing")
    ida_close.add_argument("--no-save", dest="save", action="store_false", help="Do not save IDB before closing")
    ida_close.add_argument("--json", action="store_true", help="Print JSON output")
    ida_close.set_defaults(handler=_cmd_ida_close)

    ida_list = ida_subparsers.add_parser("list", help="List registered IDA instances")
    ida_list.add_argument("--json", action="store_true", help="Print JSON output")
    ida_list.set_defaults(handler=_cmd_ida_list)

    ida_select = ida_subparsers.add_parser("select", help="Select or validate a target instance port")
    ida_select.add_argument("--port", type=int, default=None, help="Target instance port")
    ida_select.add_argument("--json", action="store_true", help="Print JSON output")
    ida_select.set_defaults(handler=_cmd_ida_select)

    instances_parser = subparsers.add_parser("instances", help="Alias for ida instance inspection")
    instances_subparsers = instances_parser.add_subparsers(dest="instances_command")
    instances_list = instances_subparsers.add_parser("list", help="List registered IDA instances")
    instances_list.add_argument("--json", action="store_true", help="Print JSON output")
    instances_list.set_defaults(handler=_cmd_ida_list)

    tool_parser = subparsers.add_parser("tool", help="Direct tool invocation via the gateway")
    tool_subparsers = tool_parser.add_subparsers(dest="tool_command")

    tool_call = tool_subparsers.add_parser("call", help="Call a proxy tool directly")
    tool_call.add_argument("tool_name", help="Tool name")
    tool_call.add_argument("--port", type=int, default=None, help="Target instance port")
    tool_call.add_argument("--timeout", type=int, default=None, help="Timeout in seconds")
    tool_call.add_argument("--params", default="{}", help="Tool params as a JSON object")
    tool_call.add_argument("--json", action="store_true", help="Print JSON output")
    tool_call.set_defaults(handler=_cmd_tool_call)

    resource_parser = subparsers.add_parser("resource", help="Read direct-instance MCP resources")
    resource_subparsers = resource_parser.add_subparsers(dest="resource_command")

    resource_read = resource_subparsers.add_parser("read", help="Read a resource from a direct instance")
    resource_read.add_argument("uri", help="Resource URI to read")
    resource_read.add_argument("--port", type=int, default=None, help="Target instance port")
    resource_read.add_argument("--timeout", type=int, default=None, help="Timeout in seconds")
    resource_read.add_argument("--json", action="store_true", help="Print JSON output")
    resource_read.set_defaults(handler=_cmd_resource_read)

    resource_list = resource_subparsers.add_parser("list", help="List direct-instance resources")
    resource_list.add_argument("--port", type=int, default=None, help="Target instance port")
    resource_list.add_argument("--timeout", type=int, default=None, help="Timeout in seconds")
    resource_list.add_argument("--json", action="store_true", help="Print JSON output")
    resource_list.set_defaults(handler=_cmd_resource_list)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return EXIT_USAGE
    try:
        return int(handler(args))
    except KeyboardInterrupt:
        payload = control.error_payload("interrupted", "Command interrupted.")
        _print_error(payload)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
