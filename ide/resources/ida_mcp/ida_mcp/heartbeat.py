import os
import threading
import time

from ida_mcp import registry

_hb_thread: threading.Thread | None = (
    None  # heartbeat/keepalive thread (monitors coordinator state and periodically refreshes registration)
)
_hb_stop = threading.Event()  # heartbeat thread stop signal (set in stop_server)
_last_register_ts: float | None = (
    None  # timestamp of the most recent successful registry.init_and_register call (updated only on re-registration after loss)
)
_ENABLE_PERIODIC_REFRESH = (
    False  # set to True to enable "timeout periodic refresh" logic; by default only re-register on loss
)
_REGISTER_INTERVAL = 300  # (optional) original threshold for periodic refresh; disabled by default
_HEARTBEAT_INTERVAL = 5  # heartbeat loop wake/polling interval
_HEARTBEAT_WARN_INTERVAL = 300  # minimum interval between repeated heartbeat failure warnings
_cached_input_file: str | None = (
    None  # cached input binary path (initialized on main thread only; heartbeat thread avoids calling IDA API directly)
)
_cached_idb_path: str | None = (
    None  # cached IDB path (same as above; avoid background thread accessing IDA C interface)
)
_hb_failure_count = 0  # consecutive heartbeat re-registration failure count
_hb_last_failure_sig: str | None = None  # most recent heartbeat failure signature
_hb_last_warn_ts = 0.0  # most recent heartbeat warning timestamp
_last_main_thread_tick_at: float | None = None
_MAIN_THREAD_TICK_INTERVAL = 5.0

_active_port_getter = None
_uv_server_getter = None


def _now_ts() -> str:
    return time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"


def _log(level: str, msg: str):
    """Unified log output with timestamp (HH:MM:SS.mmm)."""
    print(f"[IDA-MCP][{level}][{_now_ts()}] {msg}")


def _info(msg: str):
    _log("INFO", msg)


def _warn(msg: str):
    _log("WARN", msg)


def configure_state_getters(*, active_port_getter=None, uv_server_getter=None) -> None:
    global _active_port_getter, _uv_server_getter
    if active_port_getter is not None:
        _active_port_getter = active_port_getter
    if uv_server_getter is not None:
        _uv_server_getter = uv_server_getter


def _get_active_port() -> int | None:
    if _active_port_getter is None:
        return None
    return _active_port_getter()


def _get_uv_server():
    if _uv_server_getter is None:
        return None
    return _uv_server_getter()


def set_path_cache(input_file, idb_path):
    global _cached_input_file, _cached_idb_path
    _cached_input_file = input_file
    _cached_idb_path = idb_path


def get_path_cache() -> tuple[str | None, str | None]:
    return _cached_input_file, _cached_idb_path


def set_main_thread_tick(ts=None):
    global _last_main_thread_tick_at
    _last_main_thread_tick_at = time.time() if ts is None else ts


def clear_main_thread_tick() -> None:
    global _last_main_thread_tick_at
    _last_main_thread_tick_at = None


def _report_heartbeat_failure(error_text: str) -> None:
    """Throttle repeated heartbeat registration failures in the main log."""
    global _hb_failure_count, _hb_last_failure_sig, _hb_last_warn_ts

    now = time.time()
    repeated = error_text == _hb_last_failure_sig
    _hb_failure_count += 1
    should_warn = (
        _hb_failure_count == 1
        or not repeated
        or (now - _hb_last_warn_ts) >= _HEARTBEAT_WARN_INTERVAL
    )
    if not should_warn:
        return

    suppressed = _hb_failure_count - 1
    prefix = "Heartbeat re-register failed"
    if suppressed > 0:
        prefix += f" ({suppressed} similar failure(s) suppressed)"
    _warn(f"{prefix}: {error_text}")
    _hb_last_failure_sig = error_text
    _hb_last_warn_ts = now


def _reset_heartbeat_failure_tracking(log_recovery: bool = False) -> None:
    """Clear heartbeat failure throttling state after success or shutdown."""
    global _hb_failure_count, _hb_last_failure_sig, _hb_last_warn_ts
    if log_recovery and _hb_failure_count > 0:
        _info(
            f"Heartbeat re-register recovered after {_hb_failure_count} consecutive failure(s)."
        )
    _hb_failure_count = 0
    _hb_last_failure_sig = None
    _hb_last_warn_ts = 0.0


def reset_heartbeat_failure_tracking(log_recovery: bool = False) -> None:
    _reset_heartbeat_failure_tracking(log_recovery=log_recovery)


def _heartbeat_loop():
    """Background heartbeat: periodically verify the coordinator is still reachable and
    this instance's record exists, otherwise re-register.
    """
    global _last_register_ts
    pid = os.getpid()

    # wait for server initialization (up to 10 seconds)
    for _ in range(20):
        if _hb_stop.is_set():
            _info("Heartbeat thread exit (stop signal during startup).")
            return
        if _get_uv_server() is not None:
            break
        time.sleep(0.5)

    while not _hb_stop.is_set():
        active_port = _get_active_port()
        # exit if service has already stopped
        if active_port is None:
            break
        # server may be restarting; skip this round
        if _get_uv_server() is None:
            _hb_stop.wait(_HEARTBEAT_INTERVAL)
            continue
        try:
            inst_list = registry.get_instances()
        except Exception:
            inst_list = []
        tick_at = _last_main_thread_tick_at
        tick_lag = None if tick_at is None else max(time.time() - tick_at, 0.0)
        active_port = _get_active_port()
        if active_port is not None:
            try:
                registry.update_instance_status(
                    pid=pid,
                    port=active_port,
                    lifecycle_state="ready",
                    ready=True,
                    main_thread_last_tick_at=tick_at,
                    main_thread_lag_seconds=tick_lag,
                )
            except Exception:
                pass
        need_register = False
        now = time.time()
        if not inst_list:
            need_register = True
        else:
            found = any(e.get("pid") == pid for e in inst_list)
            if not found:
                need_register = True
        # no longer perform "time-driven forced refresh" by default; only re-register when instance is missing or coordinator is rebuilt.
        if (
            not need_register
            and _ENABLE_PERIODIC_REFRESH
            and _last_register_ts
            and (now - _last_register_ts) > _REGISTER_INTERVAL
        ):
            need_register = True  # optional: restore old logic when user explicitly enables it
        active_port = _get_active_port()
        if need_register and active_port is not None:
            try:
                # use only cached paths/files to avoid background thread touching IDA API
                registry.init_and_register(active_port, _cached_input_file, _cached_idb_path)
                registry.update_instance_status(
                    pid=pid,
                    port=active_port,
                    lifecycle_state="ready",
                    ready=True,
                    main_thread_last_tick_at=tick_at,
                    main_thread_lag_seconds=tick_lag,
                )
                _last_register_ts = now
                _reset_heartbeat_failure_tracking(log_recovery=True)
                if inst_list:
                    _info(
                        "Heartbeat re-register (periodic refresh) done."
                    ) if _ENABLE_PERIODIC_REFRESH else None
                else:
                    _info(
                        "Heartbeat re-register successful (gateway rebuilt or entry missing)."
                    )
            except Exception as e:  # pragma: no cover
                _report_heartbeat_failure(str(e))
        _hb_stop.wait(_HEARTBEAT_INTERVAL)
    _info("Heartbeat thread exit.")


def start_heartbeat_thread() -> None:
    global _hb_thread, _last_register_ts
    _last_register_ts = time.time()
    if _hb_thread is None or not _hb_thread.is_alive():
        _hb_stop.clear()
        _hb_thread = threading.Thread(
            target=_heartbeat_loop, name="IDA-MCP-Heartbeat", daemon=True
        )
        _hb_thread.start()
        _info("Heartbeat thread started.")


def stop_heartbeat_thread() -> None:
    global _hb_thread
    if _hb_thread and _hb_thread.is_alive():
        _hb_stop.set()
        _hb_thread.join(timeout=3)
    _hb_thread = None
