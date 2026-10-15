"""Unit tests for the standalone MCP server composition (no live IDA)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ida_mcp import mcp_server, rpc
from ida_mcp.idapython_docs import DocsIndex, _normalize_module_name


@pytest.fixture(autouse=True)
def _registry_cleanup():
    rpc.reset_registry()

    @rpc.tool
    def sample_tool(value: int = 1) -> dict:
        """Sample backend tool."""
        return {"value": value}

    yield
    rpc.reset_registry()
    mcp_server._select_entry(None)


def test_build_server_registers_management_and_forwarded_tools():
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    for expected in (
        "open_database",
        "list_databases",
        "select_database",
        "save_database",
        "close_database",
        "check_connection",
        "ida_python_reference",
        "sample_tool",
    ):
        assert expected in names, f"missing tool {expected}"
    # close_ida is management-owned and not forwarded
    assert "close_ida" not in names


def test_forward_without_instance_returns_error_payload(monkeypatch):
    monkeypatch.setattr(mcp_server, "resolve_instance", lambda _id=None: None)
    result = mcp_server.forward("sample_tool", {"value": 5})
    assert result["error"]["code"] == "no_instance"


def test_forward_wrapper_signature_carries_instance_override():
    spec = rpc.get_tool_specs()["sample_tool"]
    wrapper = mcp_server._build_forward_wrapper(spec)
    params = list(wrapper.__signature__.parameters)
    assert params[:1] == ["value"]
    assert "instance_id" in params
    assert "timeout" in params


def test_docs_index_search_ranking():
    index = DocsIndex()
    index.build(
        fetch_modules=lambda: [
            {"module": "ida_funcs", "entries": 2},
            {"module": "ida_hexrays", "entries": 1},
        ],
        fetch_snapshot=lambda name: {
            "module": name,
            "module_doc": f"docs for {name}",
            "entries": (
                [
                    {
                        "kind": "function",
                        "module": "ida_funcs",
                        "name": "get_func",
                        "qualname": "ida_funcs.get_func",
                        "signature": "(ea)",
                        "doc": "Returns the function at ea.",
                    },
                    {
                        "kind": "function",
                        "module": "ida_funcs",
                        "name": "get_fchunk",
                        "qualname": "ida_funcs.get_fchunk",
                        "signature": "(ea)",
                        "doc": "Returns a function chunk.",
                    },
                ]
                if name == "ida_funcs"
                else [
                    {
                        "kind": "function",
                        "module": "ida_hexrays",
                        "name": "decompile",
                        "qualname": "ida_hexrays.decompile",
                        "signature": "(ea)",
                        "doc": "Decompile a function.",
                    }
                ]
            ),
        },
    )
    assert index.size == 3
    results = index.search("decompile function")
    assert results[0]["qualname"] == "ida_hexrays.decompile"
    results = index.search("get_func", module="ida_funcs")
    assert all(entry["module"] == "ida_funcs" for entry in results)
    assert results[0]["name"] == "get_func"


def test_normalize_module_name_variants():
    assert _normalize_module_name("funcs") == "ida_funcs"
    assert _normalize_module_name("ida_funcs") == "ida_funcs"
    assert _normalize_module_name("idc") == "idc"
    assert _normalize_module_name("idautils") == "idautils"


def test_no_http_transport_remains():
    """stdio is the only transport; the HTTP serving path is deleted."""
    assert not hasattr(mcp_server, "serve_http")
    assert not hasattr(mcp_server, "serve")
