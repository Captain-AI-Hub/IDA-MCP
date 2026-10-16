"""Headless idalib worker process.

Each headless database runs in its own OS process::

    python -m ida_mcp.worker <executable-or-i64> [--port N]

Startup order matters for huge databases: the bridge binds and registers
the instance FIRST (healthz answers immediately; tool calls fail fast
with "database is still loading"), then ``idapro.open_database`` runs on
the main thread (``run_auto_analysis=True`` creates and analyzes the
.i64 for raw binaries). Nothing needs the main-thread call queue while
loading — tools are gated and ``wait_for_analysis`` blocks on the ready
event — so callers can attach in seconds and poll instead of waiting out
the whole analysis inside one tool call. Once the database is ready the
gate opens and the registry entry is refreshed with the real paths.
Shutdown (``POST /shutdown`` or SIGTERM) saves the database and exits.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading


def _log(message: str) -> None:
    print(f"[IDA-MCP-Worker] {message}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ida_mcp.worker",
        description="Headless IDA-MCP idalib worker",
    )
    parser.add_argument("target", help="Executable or .i64/.idb database to open")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("IDA_MCP_PORT") or 0) or 13337,
    )
    args = parser.parse_args(argv)

    # Must be set before ida_mcp imports so sync.py dispatches directly
    # instead of marshalling onto an IDA GUI main thread.
    os.environ["IDA_MCP_IDALIB"] = "1"

    # idapro must be the first IDA import; the database must be open before
    # any other ida_* module is imported (per the idalib documentation).
    import idapro  # noqa: E402  (first IDA import; activates idalib)

    from . import bridge_server
    from .config import load_config

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        _log(f"target not found: {target}")
        return 2

    load_config()

    db_ready = threading.Event()
    meta_cache: dict = {"target": target}

    def read_meta() -> dict:
        # Before the database opens only the cached target is reportable;
        # afterwards the SDK calls run on the main thread.
        meta = dict(meta_cache)
        if db_ready.is_set():
            try:
                import ida_loader  # noqa: E402
                import ida_nalt   # noqa: E402
                import idaapi     # noqa: E402

                meta.update(
                    {
                        "input_file": ida_nalt.get_input_file_path() or "",
                        "database_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
                        "ida_version": idaapi.get_kernel_version() or "",
                    }
                )
            except Exception:  # noqa: BLE001 - meta is best effort
                pass
        else:
            meta["loading"] = True
        return meta

    stop_event = threading.Event()

    def on_shutdown(save: bool) -> None:
        stop_event.set()

    server = bridge_server.BridgeServer(
        host=bridge_server.BRIDGE_HOST,
        port=args.port,
        headless=True,
        get_meta=read_meta,
        on_shutdown=on_shutdown,
        # input_file is unknown until the database finishes loading; publish
        # the target so a second open_database of the same file attaches to
        # this loading worker instead of spawning a duplicate.
        registry_extra={"target": target},
    )

    def collect_meta() -> dict:
        # Once loaded, HTTP handler threads must hop onto the main thread
        # under idalib; while loading, read_meta only touches the cache.
        if db_ready.is_set() and threading.current_thread() is not threading.main_thread():
            return server.state.run_on_main(read_meta).result()
        return read_meta()

    server.state.get_meta = collect_meta

    # 1) Bind + register first so open_database callers can attach within
    #    seconds even when loading a multi-GB database takes minutes.
    server.state.loading = True
    server.state.ready_event.clear()
    try:
        port = server.start()
    except OSError as exc:
        _log(f"failed to bind bridge on {bridge_server.BRIDGE_HOST}:{args.port}: {exc}")
        return 4
    _log(f"bridge listening on {bridge_server.BRIDGE_HOST}:{port} (instance {server.instance_id})")

    # 2) Open the database on the main thread (idalib requires it). The
    #    loading gate keeps tool calls away while we are blocked here;
    #    wait_for_analysis sleepers block on ready_event.
    _log(f"opening database (auto-analysis): {target}")
    code = idapro.open_database(target, run_auto_analysis=True)
    if code != 0:
        _log(f"idapro.open_database failed with code {code}")
        # Wake sleepers so their HTTP calls fail with a real timeout
        # instead of hanging forever.
        server.state.ready_event.set()
        server.stop()
        return 3

    from .api_loader import ensure_api_modules_loaded
    from .sync import wait_for_auto_analysis

    ensure_api_modules_loaded()
    wait_for_auto_analysis()
    db_ready.set()
    server.state.loading = False
    server.state.ready_event.set()
    server._publish()  # refresh the registry entry with real paths
    _log("database ready")

    def _signal_handler(signum, _frame):  # type: ignore[no-untyped-def]
        _log(f"signal {signum} received; shutting down")
        stop_event.set()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        # Main thread = the only thread allowed to touch the idalib SDK:
        # serve queued bridge calls until shutdown is requested.
        while not stop_event.is_set():
            server.state.process_main_calls(timeout=0.2)
    finally:
        # Drain anything queued while shutdown was requested.
        server.state.process_main_calls(timeout=0.0)
        if not os.environ.get("IDA_MCP_WORKER_NO_SAVE"):
            try:
                _log("saving database")
                import idc

                idc.save_database("")
            except Exception as exc:  # noqa: BLE001 - save is best effort
                _log(f"save failed: {exc}")
        server.stop()
        _log("closing database")
        try:
            idapro.close_database()
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
