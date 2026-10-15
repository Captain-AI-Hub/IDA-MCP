"""Unit tests for the in-instance bridge server (no live IDA)."""

from __future__ import annotations

import json
import queue as queue_module
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ida_mcp import bridge_server, rpc


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("IDA_MCP_CONFIG_ENABLE_UNSAFE", "false")
    from ida_mcp import config

    config._cached_config = None
    rpc.reset_registry()

    @rpc.tool
    def echo(value: str = "hi") -> dict:
        """Echo the value back."""
        return {"echo": value}

    yield
    rpc.reset_registry()
    config._cached_config = None


@pytest.fixture
def server():
    srv = bridge_server.BridgeServer(
        host="127.0.0.1",
        port=0,
        headless=False,
        get_meta=lambda: {"input_file": "/tmp/x.exe", "ida_version": "9.4"},
    )
    port = srv.start()
    yield srv, port
    srv.stop(unregister=False)


def _request(port: int, method: str, path: str, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def test_healthz(server):
    _srv, port = server
    assert _request(port, "GET", "/healthz") == {"ok": True}


def test_meta_wrapped_in_result(server):
    _srv, port = server
    document = _request(port, "GET", "/meta")
    assert document["result"]["input_file"] == "/tmp/x.exe"


def test_rpc_tool_call(server):
    _srv, port = server
    document = _request(port, "POST", "/rpc", {"tool": "echo", "params": {"value": "ok"}})
    assert document == {"result": {"echo": "ok"}}


def test_rpc_unknown_tool_is_404(server):
    _srv, port = server
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(port, "POST", "/rpc", {"tool": "missing", "params": {}})
    assert excinfo.value.code == 404


def test_rpc_all_tools_available(server):
    """No unsafe gating anymore: every registered tool is callable."""
    _srv, port = server
    document = _request(port, "POST", "/rpc", {"tool": "echo", "params": {}})
    assert document["result"] == {"echo": "hi"}


def test_unknown_route_is_404(server):
    _srv, port = server
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _request(port, "GET", "/nope")
    assert excinfo.value.code == 404


def test_main_queue_executes_on_draining_thread(server):
    """Queued calls execute when the main (draining) thread processes them."""
    srv, _port = server
    future = srv.state.run_on_main(lambda: 42)
    assert not future.done()
    while not future.done():
        try:
            fn, pending = srv.state.main_queue.get_nowait()
        except queue_module.Empty:
            break
        srv.state._run_main_call(fn, pending)
    assert future.result() == 42
