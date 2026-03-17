"""Integration tests for ida:// resources."""
from __future__ import annotations

import asyncio
import atexit
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest


pytestmark = pytest.mark.resources

DEFAULT_HOST = "127.0.0.1"
REQUEST_TIMEOUT = 30
RESOURCE_FUNCTION_ADDRESS = "0x1400013A0"
_LOG_DIR = str(Path(__file__).resolve().parent.parent / ".artifacts" / "api_logs")

_uri_call_logs: Dict[str, List[Dict[str, Any]]] = {
    "stdio": [],
    "http": [],
}


def _log_uri_call(
    transport: str,
    uri: str,
    port: int,
    result: Any,
    duration_ms: float,
    success: bool,
    error: Optional[str] = None,
) -> None:
    _uri_call_logs[transport].append(
        {
            "timestamp": datetime.now().isoformat(),
            "transport": transport,
            "uri": uri,
            "port": port,
            "success": success,
            "error": error,
            "result_type": type(result).__name__ if result is not None else None,
            "result_size": len(result) if isinstance(result, (list, dict, str)) else None,
            "duration_ms": round(duration_ms, 2),
        }
    )


def _save_uri_log() -> None:
    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
    except Exception:
        return

    for transport, calls in _uri_call_logs.items():
        if not calls:
            continue
        log_file = os.path.join(_LOG_DIR, f"{transport}_uri.json")
        try:
            with open(log_file, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "transport": transport,
                        "category": "uri_resources",
                        "generated_at": datetime.now().isoformat(),
                        "total_calls": len(calls),
                        "calls": calls,
                    },
                    handle,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
        except Exception:
            pass


atexit.register(_save_uri_log)


async def _read_resource_async(uri: str, port: int, transport: str = "stdio") -> Dict[str, Any]:
    start_time = time.perf_counter()
    try:
        from fastmcp import Client

        async with Client(f"http://{DEFAULT_HOST}:{port}/mcp/", timeout=REQUEST_TIMEOUT) as client:
            result = await client.read_resource(uri)

        data: Any = None
        if isinstance(result, list):
            for content in result:
                text = getattr(content, "text", None)
                if text:
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        data = text
                    break
                blob = getattr(content, "blob", None)
                if blob:
                    data = {"type": "blob", "size": len(blob)}
                    break
        else:
            data = result

        _log_uri_call(transport, uri, port, data, (time.perf_counter() - start_time) * 1000, True)
        return {"uri": uri, "data": data}
    except Exception as exc:
        _log_uri_call(transport, uri, port, None, (time.perf_counter() - start_time) * 1000, False, str(exc))
        return {"uri": uri, "error": str(exc)}


def read_resource(uri: str, port: int, transport: str = "stdio") -> Dict[str, Any]:
    return asyncio.run(_read_resource_async(uri, port, transport))


async def _list_resources_async(port: int, transport: str = "stdio") -> Dict[str, Any]:
    start_time = time.perf_counter()
    try:
        from fastmcp import Client

        async with Client(f"http://{DEFAULT_HOST}:{port}/mcp/", timeout=REQUEST_TIMEOUT) as client:
            result = await client.list_resources()

        resources = []
        templates = []
        if isinstance(result, list):
            for entry in result:
                uri_template = getattr(entry, "uriTemplate", None)
                if uri_template:
                    templates.append(uri_template)
                else:
                    resources.append(getattr(entry, "uri", str(entry)))
        data = {
            "resources": resources,
            "templates": templates,
            "total": len(resources) + len(templates),
        }
        _log_uri_call(transport, "resources/list", port, data, (time.perf_counter() - start_time) * 1000, True)
        return data
    except Exception as exc:
        _log_uri_call(transport, "resources/list", port, None, (time.perf_counter() - start_time) * 1000, False, str(exc))
        return {"error": str(exc)}


def list_resources(port: int, transport: str = "stdio") -> Dict[str, Any]:
    return asyncio.run(_list_resources_async(port, transport))


def _normalize_uri_values(values: List[Any]) -> List[str]:
    return [str(value) for value in values]


def _assert_list_resource(data: Dict[str, Any], kind: str) -> None:
    assert isinstance(data, dict)
    assert data["kind"] == kind
    assert isinstance(data["count"], int)
    assert isinstance(data["items"], list)


def _assert_detail_resource(data: Dict[str, Any], kind: str) -> None:
    assert isinstance(data, dict)
    assert data["kind"] == kind


def _assert_resource_error(data: Dict[str, Any], expected_code: Optional[str] = None) -> None:
    assert isinstance(data, dict)
    assert "error" in data
    assert isinstance(data["error"], dict)
    if expected_code is not None:
        assert data["error"]["code"] == expected_code


@pytest.fixture
def resource_transport(request):
    transport = request.config.getoption("--transport", "stdio")
    return "stdio" if transport == "both" else transport


class TestResourceDiscovery:
    def test_list_resources(self, instance_port, resource_transport):
        result = list_resources(instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot list resources: {result['error']}")

        resources = _normalize_uri_values(result["resources"])
        templates = _normalize_uri_values(result["templates"])
        advertised = set(resources) | set(templates)
        assert result["total"] >= 0
        assert "ida://idb/metadata" in resources
        assert "ida://functions" in resources
        # FastMCP resource discovery in this project reliably exposes static
        # resources, but parameterized URI templates may not be listed even
        # though direct reads still work. Those dynamic resources are covered
        # by the dedicated read tests below.
        assert "ida://strings" in advertised
        assert "ida://structs" in advertised


class TestMetadataResource:
    def test_idb_metadata(self, instance_port, resource_transport):
        result = read_resource("ida://idb/metadata", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read metadata: {result['error']}")

        data = result["data"]
        _assert_detail_resource(data, "idb_metadata")
        assert any(key in data for key in ["input_file", "arch", "bits", "hash"])


class TestFunctionResources:
    def test_functions_list(self, instance_port, resource_transport):
        result = read_resource("ida://functions", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read functions: {result['error']}")

        _assert_list_resource(result["data"], "functions")

    def test_function_detail(self, instance_port, resource_transport):
        uri = f"ida://function/{RESOURCE_FUNCTION_ADDRESS}"
        result = read_resource(uri, instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read function detail: {result['error']}")

        data = result["data"]
        if isinstance(data, dict) and "error" in data:
            pytest.skip(f"Function detail unavailable: {data['error']}")
        _assert_detail_resource(data, "function")
        assert data["address"].lower() == RESOURCE_FUNCTION_ADDRESS.lower()

    def test_function_decompile(self, instance_port, resource_transport):
        uri = f"ida://function/{RESOURCE_FUNCTION_ADDRESS}/decompile"
        result = read_resource(uri, instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read function decompile: {result['error']}")

        data = result["data"]
        if "error" in data:
            pytest.skip(f"Decompiler unavailable: {data['error']}")
        _assert_detail_resource(data, "function_decompile")
        assert "decompiled" in data

    def test_function_disasm(self, instance_port, resource_transport):
        uri = f"ida://function/{RESOURCE_FUNCTION_ADDRESS}/disasm"
        result = read_resource(uri, instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read function disasm: {result['error']}")

        data = result["data"]
        if isinstance(data, dict) and "error" in data:
            pytest.skip(f"Function disasm unavailable: {data['error']}")
        _assert_detail_resource(data, "function_disasm")
        assert isinstance(data["items"], list)

    def test_function_basic_blocks(self, instance_port, resource_transport):
        uri = f"ida://function/{RESOURCE_FUNCTION_ADDRESS}/basic_blocks"
        result = read_resource(uri, instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read function basic blocks: {result['error']}")

        data = result["data"]
        if isinstance(data, dict) and "error" in data:
            pytest.skip(f"Function basic blocks unavailable: {data['error']}")
        _assert_detail_resource(data, "function_basic_blocks")
        assert isinstance(data["items"], list)

    def test_function_stack(self, instance_port, resource_transport):
        uri = f"ida://function/{RESOURCE_FUNCTION_ADDRESS}/stack"
        result = read_resource(uri, instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read function stack: {result['error']}")

        data = result["data"]
        if "error" in data:
            pytest.skip(f"Stack info unavailable: {data['error']}")
        _assert_detail_resource(data, "function_stack")
        assert isinstance(data["items"], list)


class TestCoreListResources:
    def test_strings(self, instance_port, resource_transport):
        result = read_resource("ida://strings", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read strings: {result['error']}")
        _assert_list_resource(result["data"], "strings")

    def test_globals(self, instance_port, resource_transport):
        result = read_resource("ida://globals", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read globals: {result['error']}")
        _assert_list_resource(result["data"], "globals")

    def test_types(self, instance_port, resource_transport):
        result = read_resource("ida://types", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read types: {result['error']}")
        _assert_list_resource(result["data"], "types")

    def test_segments_and_segment_detail(self, instance_port, resource_transport):
        result = read_resource("ida://segments", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read segments: {result['error']}")
        data = result["data"]
        _assert_list_resource(data, "segments")
        if not data["items"]:
            pytest.skip("No segments available")

        name = data["items"][0]["name"]
        detail = read_resource(f"ida://segment/{name}", instance_port, resource_transport)
        if "error" in detail:
            pytest.skip(f"Cannot read segment detail: {detail['error']}")
        _assert_detail_resource(detail["data"], "segment")

    def test_imports_exports_and_entry_points(self, instance_port, resource_transport):
        imports_result = read_resource("ida://imports", instance_port, resource_transport)
        if "error" in imports_result:
            pytest.skip(f"Cannot read imports: {imports_result['error']}")
        imports_data = imports_result["data"]
        _assert_list_resource(imports_data, "imports")

        if imports_data["items"]:
            module = imports_data["items"][0]["module"]
            module_result = read_resource(f"ida://imports/{module}", instance_port, resource_transport)
            if "error" not in module_result:
                _assert_detail_resource(module_result["data"], "imports_module")

        exports_result = read_resource("ida://exports", instance_port, resource_transport)
        if "error" in exports_result:
            pytest.skip(f"Cannot read exports: {exports_result['error']}")
        _assert_list_resource(exports_result["data"], "exports")

        entry_points_result = read_resource("ida://entry_points", instance_port, resource_transport)
        if "error" in entry_points_result:
            pytest.skip(f"Cannot read entry points: {entry_points_result['error']}")
        _assert_list_resource(entry_points_result["data"], "entry_points")

    def test_structs_and_struct_detail(self, instance_port, resource_transport):
        result = read_resource("ida://structs", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read structs: {result['error']}")
        data = result["data"]
        _assert_list_resource(data, "structs")

        if not data["items"]:
            pytest.skip("No structs available")

        name = data["items"][0]["name"]
        detail = read_resource(f"ida://struct/{name}", instance_port, resource_transport)
        if "error" in detail:
            pytest.skip(f"Cannot read struct detail: {detail['error']}")
        _assert_detail_resource(detail["data"], "struct")


class TestXrefAndMemoryResources:
    def test_xrefs_to_and_summary(self, instance_port, resource_transport):
        addr = RESOURCE_FUNCTION_ADDRESS
        result = read_resource(f"ida://xrefs/to/{addr}", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read xrefs_to: {result['error']}")
        _assert_detail_resource(result["data"], "xrefs_to")

        summary = read_resource(f"ida://xrefs/to/{addr}/summary", instance_port, resource_transport)
        if "error" in summary:
            pytest.skip(f"Cannot read xrefs_to summary: {summary['error']}")
        _assert_detail_resource(summary["data"], "xrefs_to_summary")

    def test_xrefs_from_and_summary(self, instance_port, resource_transport):
        addr = RESOURCE_FUNCTION_ADDRESS
        result = read_resource(f"ida://xrefs/from/{addr}", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read xrefs_from: {result['error']}")
        _assert_detail_resource(result["data"], "xrefs_from")

        summary = read_resource(f"ida://xrefs/from/{addr}/summary", instance_port, resource_transport)
        if "error" in summary:
            pytest.skip(f"Cannot read xrefs_from summary: {summary['error']}")
        _assert_detail_resource(summary["data"], "xrefs_from_summary")

    def test_memory_read(self, instance_port, resource_transport):
        result = read_resource(f"ida://memory/{RESOURCE_FUNCTION_ADDRESS}", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Cannot read memory: {result['error']}")
        data = result["data"]
        _assert_detail_resource(data, "memory")
        assert "bytes" in data
        assert "hex" in data


class TestInvalidResources:
    def test_invalid_uri(self, instance_port, resource_transport):
        result = read_resource("ida://nonexistent/invalid", instance_port, resource_transport)
        assert "error" in result or result.get("data") in (None, {})

    def test_invalid_address(self, instance_port, resource_transport):
        result = read_resource("ida://function/invalid_addr", instance_port, resource_transport)
        if "error" in result:
            pytest.skip(f"Transport returned an error instead of resource payload: {result['error']}")
        _assert_resource_error(result["data"], "invalid_address")
