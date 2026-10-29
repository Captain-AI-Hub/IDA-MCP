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


def _request_json(port: int, method: str, path: str, payload=None):
    """Like _request but returns the JSON body of 4xx/5xx responses too."""
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read().decode("utf-8"))


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


def test_loading_gate(server):
    """Tool calls fail fast while the database is loading."""
    srv, port = server
    srv.state.loading = True
    srv.state.ready_event.clear()
    try:
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            _request(port, "POST", "/rpc", {"tool": "echo", "params": {}})
        assert excinfo.value.code == 500
        assert "loading" in excinfo.value.read().decode()
    finally:
        srv.state.loading = False
        srv.state.ready_event.set()


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


# ============================================================================
# Operation cancellation (interrupt long-running tool calls)
# ============================================================================


def test_cancel_operation_interrupts_in_flight_call(server):
    """A running tool gets _OperationInterrupt injected and unwinds quickly."""
    import threading
    import time

    srv, port = server
    started = threading.Event()
    stopped = threading.Event()

    @rpc.tool
    def spin(block: bool = False) -> dict:
        """Spin forever until interrupted."""
        started.set()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            pass  # a pure-Python loop is interruptible via async exception
        stopped.set()
        return {"finished": True}

    result_holder: queue_module.Queue = queue_module.Queue()

    def call():
        try:
            result_holder.put(("ok", _request(
                port, "POST", "/rpc",
                {"tool": "spin", "params": {}, "timeout": 30, "operation_id": "op-1"},
            )))
        except Exception as exc:  # noqa: BLE001 - HTTP layer raises on 504
            result_holder.put(("exc", exc))

    caller = threading.Thread(target=call)
    caller.start()
    assert started.wait(5.0), "tool never started"

    # Cancel while the tool is spinning.
    deadline = time.monotonic() + 3.0
    cancelled = False
    while time.monotonic() < deadline:
        response = _request(port, "POST", "/cancel_operation", {"operation_id": "op-1"})
        if response.get("result", {}).get("cancelled"):
            cancelled = True
            break
        time.sleep(0.02)
    assert cancelled, "cancel_operation never found the active operation"

    kind, payload = result_holder.get(timeout=5.0)
    assert kind == "exc"
    # The injected interrupt tears the in-flight request down as a gateway
    # timeout (the worker surfaced a structured timeout error) or a closed
    # socket (the handler unwound mid-response). Either way the loop was
    # interrupted rather than running to completion.
    # 504 is the bridge's structured "tool call timed out on the IDA side".
    message = str(payload)
    assert "504" in message or "closed connection" in message, message
    # The interrupted loop exited well before its own 5s deadline.
    assert not stopped.is_set()
    caller.join(timeout=5.0)


def test_cancel_unknown_operation_is_noop(server):
    srv, port = server
    response = _request(port, "POST", "/cancel_operation", {"operation_id": "nope"})
    assert response == {"result": {"cancelled": False}}


def test_rpc_rejects_client_supplied_operation_param(server):
    """_operation_id is server-assigned; clients must not smuggle it in params."""
    srv, port = server
    response = _request_json(
        port, "POST", "/rpc",
        {"tool": "echo", "params": {"_operation_id": "evil"}, "timeout": 5},
    )
    assert response["error"]["code"] == "invalid_params"


def test_untracked_call_without_operation_id_behaves_as_before(server):
    """Calls without operation_id keep the old fire-and-forget behavior."""
    srv, port = server
    response = _request(port, "POST", "/rpc", {"tool": "echo", "params": {"value": "x"}})
    assert response["result"]["echo"] == "x"
