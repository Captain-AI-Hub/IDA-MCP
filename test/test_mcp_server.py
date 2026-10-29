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


def test_build_server_registers_management_and_forwarded_tools():
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    for expected in (
        "open_database",
        "list_databases",
        "save_database",
        "close_database",
        "check_connection",
        "ida_python_reference",
        "sample_tool",
    ):
        assert expected in names, f"missing tool {expected}"
    # Default-selection was removed: routing is per-call via instance_id.
    assert "select_database" not in names
    # close_ida is management-owned and not forwarded
    assert "close_ida" not in names


def test_forward_without_instance_returns_error_payload(monkeypatch):
    from ida_mcp import bridge_client as bc
    from ida_mcp import instances as instances_mod

    monkeypatch.setattr(mcp_server, "resolve_instance", lambda _id=None: None)
    monkeypatch.setattr(instances_mod, "list_live_instances", lambda: [])
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


def test_stateless_routing_rules(monkeypatch):
    """No default selection exists: dead explicit ids error, the sole live
    instance is the implicit target, and several live instances without an
    explicit id fail loudly instead of routing to an arbitrary database."""
    from ida_mcp import bridge_client as bc
    from ida_mcp import instances as instances_mod

    sole = {"instance_id": "i-sole", "port": 13400, "pid": 2, "input_file": "a.exe"}
    second = {"instance_id": "i-second", "port": 13402, "pid": 3, "input_file": "b.exe"}
    monkeypatch.setattr(bc, "is_alive", lambda entry: entry["instance_id"] != "i-dead")
    registry = {
        "i-sole": sole,
        "i-second": second,
        "i-dead": {"instance_id": "i-dead", "input_file": "dead.exe"},
    }
    monkeypatch.setattr(instances_mod, "find_by_id", lambda iid: registry.get(iid))

    # A dead explicit id errors and never falls through to another database.
    monkeypatch.setattr(instances_mod, "list_live_instances", lambda: [sole])
    result = mcp_server.forward("sample_tool", {}, instance_id="i-dead")
    assert result["error"]["code"] == "instance_gone"
    assert "i-dead" in result["error"]["message"]

    # An unknown explicit id is reported as not found.
    result = mcp_server.forward("sample_tool", {}, instance_id="i-nope")
    assert result["error"]["code"] == "instance_not_found"

    # Sole live instance is the implicit target.
    picked = mcp_server.resolve_instance()
    assert picked and picked["instance_id"] == "i-sole"

    # Several live instances without an explicit id -> loud ambiguity error.
    monkeypatch.setattr(instances_mod, "list_live_instances", lambda: [sole, second])
    result = mcp_server.forward("sample_tool", {})
    assert result["error"]["code"] == "instance_ambiguous"
    assert "i-sole" in result["error"]["message"]
    assert "i-second" in result["error"]["message"]
    # The error must tell the model to retry with instance_id (not to
    # pick another action).
    assert "retry" in result["error"]["message"]

    # ... while an explicit id still routes deterministically.
    picked = mcp_server.resolve_instance("i-second")
    assert picked and picked["instance_id"] == "i-second"


def test_close_database_respects_other_holders(tmp_path, monkeypatch):
    """Shared headless worker survives close while another pid holds a lease."""
    from ida_mcp import lifecycle as lc

    entry = {"instance_id": "i-shared", "pid": 999, "port": 13401, "headless": True}
    monkeypatch.setattr(lc.instances, "lease_holders", lambda iid: [424242])
    monkeypatch.setattr(lc.instances, "lease_remove", lambda iid, pid: None)
    result = lc.close_database(entry, terminate=False, save=False)
    assert result["status"] == "released"
    assert result["remaining_users"] == 1
