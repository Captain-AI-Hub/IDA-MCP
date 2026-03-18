from __future__ import annotations

import sys
import types

from ida_mcp import server_factory
from ida_mcp.proxy import register_tools
from ida_mcp.rpc import ToolSpec, get_tool_specs


class _FakeProxyServer:
    def __init__(self) -> None:
        self.tool_names: list[str] = []

    def tool(self, description: str = ""):
        def decorator(fn):
            self.tool_names.append(fn.__name__)
            return fn

        return decorator


class _FakeFastMCP:
    def __init__(self, name: str, instructions: str) -> None:
        self.name = name
        self.instructions = instructions
        self.tools: list[str] = []
        self.resources: list[str] = []

    def tool(self, description: str = ""):
        def decorator(fn):
            self.tools.append(fn.__name__)
            return fn

        return decorator

    def resource(self, uri: str):
        if uri == "ida://broken":
            raise RuntimeError("boom")

        def decorator(fn):
            self.resources.append(uri)
            return fn

        return decorator


def test_proxy_registers_convert_number(monkeypatch):
    monkeypatch.setattr(register_tools, "is_unsafe_enabled", lambda: False)
    server = _FakeProxyServer()

    register_tools.register_tools(server)

    assert "convert_number" in server.tool_names


def test_proxy_registers_structured_analysis_tools(monkeypatch):
    monkeypatch.setattr(register_tools, "is_unsafe_enabled", lambda: False)
    server = _FakeProxyServer()

    register_tools.register_tools(server)

    for tool_name in (
        "get_callers",
        "get_callees",
        "get_function_signature",
    ):
        assert tool_name in server.tool_names


def test_proxy_registers_consolidated_memory_and_type_tools(monkeypatch):
    monkeypatch.setattr(register_tools, "is_unsafe_enabled", lambda: False)
    server = _FakeProxyServer()

    register_tools.register_tools(server)

    for tool_name in (
        "read_scalar",
        "declare_struct",
        "declare_enum",
        "declare_typedef",
    ):
        assert tool_name in server.tool_names

    for removed_name in (
        "get_u8",
        "get_u16",
        "get_u32",
        "get_u64",
        "create_array",
        "declare_type",
        "get_function",
        "get_pseudocode_function",
        "get_pseudocode_lines",
    ):
        assert removed_name not in server.tool_names


def test_proxy_registration_matches_backend_registry(monkeypatch):
    monkeypatch.setattr(register_tools, "is_unsafe_enabled", lambda: False)
    server = _FakeProxyServer()

    register_tools.register_tools(server)
    server_factory._ensure_api_modules_loaded()

    expected = {
        name
        for name, spec in get_tool_specs().items()
        if name not in {"check_connection", "list_instances", "close_ida"} and not spec.unsafe
    }
    expected.update({"open_in_ida", "close_ida", "shutdown_gateway"})

    assert set(server.tool_names) == expected


def test_proxy_skips_unsafe_backend_tools_when_disabled(monkeypatch):
    monkeypatch.setattr(register_tools, "is_unsafe_enabled", lambda: False)
    server = _FakeProxyServer()

    register_tools.register_tools(server)

    for tool_name in ("py_eval", "dbg_regs", "dbg_continue", "dbg_write_mem"):
        assert tool_name not in server.tool_names


def test_tool_metadata_tracks_unsafe_and_execution_mode():
    server_factory._ensure_api_modules_loaded()

    py_eval_spec = get_tool_specs()["py_eval"]
    dbg_regs_spec = get_tool_specs()["dbg_regs"]

    assert py_eval_spec.unsafe is True
    assert py_eval_spec.execution_mode == "write"
    assert dbg_regs_spec.unsafe is True


def test_create_mcp_server_logs_failed_resource_registration(monkeypatch, capsys):
    fake_fastmcp_module = types.SimpleNamespace(FastMCP=_FakeFastMCP)
    monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp_module)
    monkeypatch.setattr(server_factory, "_ensure_api_modules_loaded", lambda: None)
    monkeypatch.setattr(
        server_factory,
        "get_tool_specs",
        lambda: {
            "check_connection": ToolSpec(
                name="check_connection",
                fn=lambda: {"ok": True},
                description="Health check",
                unsafe=False,
                execution_mode="direct",
                module_name="test",
            )
        },
    )
    monkeypatch.setattr(
        server_factory,
        "get_resources",
        lambda: {
            "ida://ok": lambda: "ok",
            "ida://broken": lambda: "broken",
        },
    )

    mcp = server_factory.create_mcp_server()

    captured = capsys.readouterr()
    assert "ida://ok" in mcp.resources
    assert "Failed to register resource ida://broken" in captured.out
