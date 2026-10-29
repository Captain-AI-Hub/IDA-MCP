"""In-process JSON-RPC bridge served by every IDA-MCP instance.

One stdlib-only HTTP server runs inside each idalib worker process. It
exposes the tool/resource catalog over a private loopback endpoint and
publishes the instance in the shared JSON registry. The standalone MCP
server talks to this bridge directly; there is no gateway, port registry,
or forwarding hop anymore.

Endpoints:
    GET  /healthz           liveness probe
    GET  /meta              instance metadata (paths, version, headless flag)
    POST /rpc               {"tool": str, "params": {...}, "timeout"?: float}
    GET  /docs/modules      IDAPython modules available for documentation
    POST /docs              {"module": str} documentation snapshot
    POST /shutdown          {"save": bool} graceful instance shutdown
"""

from __future__ import annotations

import ctypes
import json
import os
import queue
import threading
import time
import traceback
from concurrent.futures import Future, ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional

from . import instances
from . import rpc
from .api_loader import ensure_api_modules_loaded
from .errors import error_payload

_MAX_BODY_BYTES = 64 * 1024 * 1024
_CALL_EXECUTOR_WORKERS = 8

# The bridge is local-only by design: fixed loopback bind, no auth.
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT_BASE = 13337


class _OperationInterrupt(BaseException):
    """Asynchronous exception used to stop long-running user code.

    Raised inside the executing thread via PyThreadState_SetAsyncExc — pure
    Python loops become cancellable without installing an opcode trace.
    Derived from BaseException so user ``except Exception`` handlers cannot
    swallow the interruption.
    """


# CPython private API (used by Hex-Rays ida-nexus the same way): inject one
# exception object into one thread state. A void-pointer argtype lets a null
# value undo the injection if CPython ever reports multiple matching states.
_set_async_exc = ctypes.pythonapi.PyThreadState_SetAsyncExc
_set_async_exc.argtypes = (ctypes.c_ulong, ctypes.c_void_p)
_set_async_exc.restype = ctypes.c_int


def _interrupt_thread(thread_id: int) -> bool:
    count = _set_async_exc(thread_id, id(_OperationInterrupt))
    if count > 1:
        _set_async_exc(thread_id, None)
        raise RuntimeError("CPython matched multiple bridge execution threads")
    return count == 1


class BridgeState:
    """Mutable state shared between the HTTP handler threads and the host."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        headless: bool,
        instance_id: str,
        get_meta: Callable[[], Dict[str, Any]],
        on_shutdown: Optional[Callable[[bool], None]] = None,
    ):
        self.host = host
        self.port = port
        self.headless = headless
        self.instance_id = instance_id
        self.get_meta = get_meta
        self.on_shutdown = on_shutdown
        self.started_at = time.time()
        self._call_executor = ThreadPoolExecutor(
            max_workers=_CALL_EXECUTOR_WORKERS,
            thread_name_prefix="IDA-MCP-Call",
        )
        self._docs_lock = threading.Lock()
        # idalib workers execute queued SDK calls on the process main thread.
        self.main_queue: "queue.Queue[tuple[Callable[[], Any], Future]]" = queue.Queue()
        # Workers open huge databases after the bridge is already serving:
        # gate tool calls until the database is ready. wait_for_analysis
        # blocks on ready_event instead of failing fast.
        self.loading = False
        self.ready_event = threading.Event()
        self.ready_event.set()
        # In-flight cancellable operations: operation_id -> thread id under
        # _active_lock; a generation counter rejects cancellations that
        # arrive after the operation already finished.
        self._active_lock = threading.Lock()
        self._active: Dict[str, int] = {}
        self._generation = 0

    # -- dispatch ----------------------------------------------------------

    def call_tool(self, name: str, params: Dict[str, Any], timeout: Optional[float]) -> Any:
        """Run one registered tool (gated while the database is loading)."""
        if self.loading and name != "wait_for_analysis":
            raise RuntimeError("database is still loading")
        if self.loading and name == "wait_for_analysis":
            if not self.ready_event.wait(timeout=timeout if timeout else None):
                raise TimeoutError("database still loading after tool timeout")
        ensure_api_modules_loaded()
        tools = rpc.get_tools()
        fn = tools.get(name)
        if fn is None:
            raise KeyError(name)
        params = dict(params or {})
        operation_id = params.pop("_operation_id", None)
        if operation_id:
            future = self._call_executor.submit(
                self._dispatch_tracked, fn, params, str(operation_id)
            )
        else:
            future = self._call_executor.submit(self._dispatch, fn, params)
        if timeout is None:
            return future.result()
        return future.result(timeout=max(float(timeout), 0.1))

    def _dispatch(self, fn: Callable, params: Dict[str, Any], operation_id: Optional[str] = None) -> Any:
        if os.environ.get("IDA_MCP_IDALIB"):
            # idalib requires SDK calls on the process main thread; the
            # worker's main loop drains this queue. The queued closure
            # re-registers the *executing* (main) thread once the code is
            # actually about to run there — rebinding before enqueue would
            # race a cancel arriving between enqueue and execution and
            # target a thread that never runs the code.
            if threading.current_thread() is threading.main_thread():
                return fn(**params)

            def run_on_worker_main() -> Any:
                self._rebind_active_thread(operation_id)
                return fn(**params)

            return self.run_on_main(run_on_worker_main).result()
        # Outside a worker (tests, tooling) run inline.
        return fn(**params)

    def _rebind_active_thread(self, operation_id: Optional[str]) -> None:
        """Point the operation's cancellation target at the main thread."""
        if operation_id is None:
            return
        try:
            with self._active_lock:
                if operation_id in self._active:
                    self._active[operation_id] = threading.main_thread().ident
        except Exception:  # noqa: BLE001 - rebinding is best effort
            pass

    def _dispatch_tracked(
        self, fn: Callable, params: Dict[str, Any], operation_id: str
    ) -> Any:
        """Dispatch with cancellation registration for this operation_id.

        While the tool runs, /cancel_operation can (a) flag IDA's native
        analysis-interrupt switch so stuck SDK calls unwind, and (b) inject
        ``_OperationInterrupt`` into the thread executing the code so
        pure-Python loops stop. The interrupt is translated here into a
        plain TimeoutError so it crosses the concurrent.futures and HTTP
        boundaries as a normal, serializable error.
        """
        with self._active_lock:
            self._active[operation_id] = threading.get_ident()
        try:
            return self._dispatch(fn, params, operation_id=operation_id)
        except _OperationInterrupt:
            raise TimeoutError(
                f"operation {operation_id} was cancelled before completion"
            ) from None
        finally:
            with self._active_lock:
                self._active.pop(operation_id, None)

    def cancel_operation(self, operation_id: str) -> bool:
        """Interrupt one in-flight operation. True when it was active."""
        with self._active_lock:
            thread_id = self._active.get(str(operation_id))
            if thread_id is None:
                return False
            # Flag IDA's native cancel switch first: SDK calls blocked inside
            # the kernel (auto-analysis, huge decompiles) unwind once set.
            try:
                import ida_kernwin  # type: ignore

                ida_kernwin.set_cancelled()
            except Exception:  # noqa: BLE001 - native flag is best effort
                pass
            _interrupt_thread(thread_id)
            self._generation += 1
            return True

    # -- main-thread executor (idalib workers) -----------------------------

    def run_on_main(self, fn: Callable[[], Any]) -> "Future[Any]":
        future: Future = Future()
        self.main_queue.put((fn, future))
        return future

    def process_main_calls(self, timeout: float = 0.2) -> bool:
        """Execute queued calls on the calling (main) thread; True if any ran."""
        try:
            fn, future = self.main_queue.get(timeout=max(timeout, 0.0))
        except queue.Empty:
            return False
        self._run_main_call(fn, future)
        while True:
            try:
                fn, future = self.main_queue.get_nowait()
            except queue.Empty:
                return True
            self._run_main_call(fn, future)

    @staticmethod
    def _run_main_call(fn: Callable[[], Any], future: "Future[Any]") -> None:
        try:
            future.set_result(fn())
        except BaseException as exc:  # noqa: BLE001 - futures must capture
            future.set_exception(exc)

    def docs_modules(self) -> list:
        from . import idapython_docs

        # vars() on some SWIG modules trips IDA's main-thread check under
        # idalib; _dispatch hops to the main thread there.
        return self._dispatch(idapython_docs.list_modules, {})

    def docs_snapshot(self, module_name: str) -> dict:
        from . import idapython_docs

        with self._docs_lock:
            return self._dispatch(
                lambda: idapython_docs.snapshot_module(module_name), {}
            )

    def shutdown(self) -> None:
        self._call_executor.shutdown(wait=False)


class BridgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "IDA-MCP-Bridge/1.0"

    @property
    def state(self) -> BridgeState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        if os.environ.get("IDA_MCP_DEBUG"):
            print(f"[IDA-MCP-Bridge] {self.address_string()} {fmt % args}")

    # -- helpers -----------------------------------------------------------

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > _MAX_BODY_BYTES:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _guarded(self, action: Callable[[], Any]) -> None:
        try:
            self._send_json({"result": action()})
        except KeyError as exc:
            self._send_json(
                error_payload("not_found", f"Unknown tool or resource: {exc}"), 404
            )
        except TimeoutError:
            self._send_json(
                error_payload("timeout", "Tool call timed out on the IDA side."), 504
            )
        except Exception as exc:  # noqa: BLE001 - RPC boundary
            self._send_json(
                error_payload(
                    "tool_failed",
                    f"{type(exc).__name__}: {exc}",
                    traceback=traceback.format_exc(limit=8),
                ),
                500,
            )

    # -- routes ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json({"ok": True})
            return
        if path == "/meta":
            try:
                self._send_json({"result": self.state.get_meta()})
            except Exception as exc:  # noqa: BLE001 - RPC boundary
                self._send_json(error_payload("meta_failed", str(exc)), 500)
            return
        if path == "/docs/modules":
            self._guarded(self.state.docs_modules)
            return
        self._send_json(error_payload("not_found", f"No route for {path}"), 404)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        try:
            payload = self._read_json()
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._send_json(error_payload("invalid_json", str(exc)), 400)
            return

        if path == "/rpc":
            name = str(payload.get("tool") or "")
            params = payload.get("params") or {}
            timeout = payload.get("timeout")
            if not isinstance(params, dict):
                self._send_json(error_payload("invalid_params", "params must be an object"), 400)
                return
            if "_operation_id" in params:
                self._send_json(
                    error_payload("invalid_params", "_operation_id is server-assigned"), 400
                )
                return
            if str(payload.get("operation_id") or ""):
                params = dict(params)
                params["_operation_id"] = str(payload.get("operation_id"))
            self._guarded(lambda: self.state.call_tool(name, params, timeout))
            return
        if path == "/cancel_operation":
            operation_id = str(payload.get("operation_id") or "")
            cancelled = self.state.cancel_operation(operation_id)
            self._send_json({"result": {"cancelled": cancelled}})
            return
        if path == "/docs":
            module_name = str(payload.get("module") or "")
            self._guarded(lambda: self.state.docs_snapshot(module_name))
            return
        if path == "/shutdown":
            save = bool(payload.get("save", True))
            self._send_json({"result": {"status": "shutdown_requested", "save": save}})
            self._request_shutdown(save)
            return
        self._send_json(error_payload("not_found", f"No route for {path}"), 404)

    def _request_shutdown(self, save: bool) -> None:
        state = self.state
        callback = state.on_shutdown
        if callback is None:
            return
        threading.Thread(
            target=callback, args=(save,), name="IDA-MCP-Shutdown", daemon=True
        ).start()


class BridgeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple, state: BridgeState):
        self.state = state  # type: ignore[attr-defined]
        super().__init__(address, BridgeHandler)


class BridgeServer:
    """Owns the HTTP listener thread and the registry entry lifecycle."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        headless: bool,
        get_meta: Callable[[], Dict[str, Any]],
        on_shutdown: Optional[Callable[[bool], None]] = None,
        registry_extra: Optional[Dict[str, Any]] = None,
    ):
        self.host = host
        self.port = port
        self.headless = headless
        self.instance_id = instances.new_instance_id()
        self.state = BridgeState(
            host=host,
            port=port,
            headless=headless,
            instance_id=self.instance_id,
            get_meta=get_meta,
            on_shutdown=on_shutdown,
        )
        self._registry_extra = registry_extra or {}
        self._http: Optional[BridgeHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._meta_cache: Dict[str, Any] = {}

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> int:
        """Bind, start serving, and publish the registry entry."""
        self._http = BridgeHTTPServer((self.host, self.port), self.state)
        self.port = self._http.server_address[1]
        self.state.port = self.port
        self._thread = threading.Thread(
            target=self._http.serve_forever,
            name="IDA-MCP-Bridge",
            daemon=True,
        )
        self._thread.start()
        self._publish()
        return self.port

    def stop(self, *, unregister: bool = True) -> None:
        http, self._http = self._http, None
        thread, self._thread = self._thread, None
        if http is not None:
            try:
                http.shutdown()
            except Exception:  # noqa: BLE001 - shutdown is best effort
                pass
            try:
                http.server_close()
            except Exception:  # noqa: BLE001
                pass
        if thread is not None:
            thread.join(timeout=2)
        self.state.shutdown()
        if unregister:
            try:
                instances.remove_instance(self.instance_id)
            except Exception:  # noqa: BLE001
                pass

    def _publish(self) -> None:
        meta = self._collect_meta()
        entry = {
            "instance_id": self.instance_id,
            "pid": os.getpid(),
            "port": self.port,
            "host": self.host if self.host else "127.0.0.1",
            "input_file": meta.get("input_file") or "",
            "database_path": meta.get("database_path") or "",
            "headless": self.headless,
            "started_at": self.state.started_at,
            "version": meta.get("version") or "",
            **self._registry_extra,
        }
        instances.add_instance(entry)

    # -- metadata ----------------------------------------------------------

    def set_meta_cache(self, **fields: Any) -> None:
        self._meta_cache.update(fields)

    def _collect_meta(self) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "instance_id": self.instance_id,
            "pid": os.getpid(),
            "port": self.port,
            "host": self.host,
            "headless": self.headless,
            "started_at": self.state.started_at,
        }
        meta.update(self._meta_cache)
        try:
            meta.update(self.state.get_meta() or {})
        except Exception:  # noqa: BLE001 - meta must never crash the bridge
            pass
        return meta

    def get_meta(self) -> Dict[str, Any]:
        return self._collect_meta()
