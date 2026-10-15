"""Headless idalib worker process.

Each headless database runs in its own OS process::

    python -m ida_mcp.worker <executable-or-i64> [--port N] [--host H]

The worker opens the database with the official ``idapro`` idalib bindings
(``idapro.open_database(..., run_auto_analysis=True)`` — creating and
analyzing the .i64 when given a raw binary), then serves the same JSON-RPC
bridge as the GUI plugin and publishes itself in the shared instance
registry. Shutdown (``POST /shutdown`` or SIGTERM) saves the database and
exits.
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

    from .config import load_config

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        _log(f"target not found: {target}")
        return 2

    load_config()
    _log(f"opening database (auto-analysis): {target}")
    # run_auto_analysis=True creates the .i64 for raw binaries and analyzes
    # existing databases before any tool call runs.
    code = idapro.open_database(target, run_auto_analysis=True)
    if code != 0:
        _log(f"idapro.open_database failed with code {code}")
        return 3

    from . import bridge_server
    from .api_loader import ensure_api_modules_loaded
    from .sync import wait_for_auto_analysis

    ensure_api_modules_loaded()
    wait_for_auto_analysis()

    import ida_loader  # noqa: E402
    import ida_nalt   # noqa: E402
    import idaapi     # noqa: E402

    def read_meta() -> dict:
        # IDALIB mode: direct calls are safe on the main thread.
        try:
            return {
                "input_file": ida_nalt.get_input_file_path() or "",
                "database_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
                "ida_version": idaapi.get_kernel_version() or "",
            }
        except Exception:  # noqa: BLE001 - meta is best effort
            return {}

    stop_event = threading.Event()

    def on_shutdown(save: bool) -> None:
        stop_event.set()

    server = bridge_server.BridgeServer(
        host=bridge_server.BRIDGE_HOST,
        port=args.port,
        headless=True,
        get_meta=read_meta,
        on_shutdown=on_shutdown,
    )

    def collect_meta() -> dict:
        # HTTP handler threads must hop onto the main thread under idalib.
        if threading.current_thread() is threading.main_thread():
            return read_meta()
        return server.state.run_on_main(read_meta).result()

    server.state.get_meta = collect_meta
    try:
        port = server.start()
    except OSError as exc:
        _log(f"failed to bind bridge on {args.host}:{args.port}: {exc}")
        return 4
    _log(f"bridge listening on {bridge_server.BRIDGE_HOST}:{port} (instance {server.instance_id})")

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
