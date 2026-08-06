"""Consume gateway lifecycle actions stored through HCLI plugin config."""

from __future__ import annotations

import threading
from typing import Any, Callable

_ACTION_KEY = "gateway"
_IDLE = "idle"
_ACTIONS = {"start", "stop", "restart"}
_POLL_INTERVAL = 0.75

_stop_event = threading.Event()
_watcher_thread: threading.Thread | None = None

LogFn = Callable[[str], None]


def _noop(_message: str) -> None:
    return None


def get_pending_gateway_action(*, warn: LogFn = _noop) -> str | None:
    """Return a pending valid action without executing or resetting it."""
    try:
        import ida_settings  # type: ignore
    except (ImportError, ModuleNotFoundError):
        return None

    try:
        raw_action = ida_settings.get_current_plugin_setting(_ACTION_KEY)
    except (KeyError, RuntimeError, ValueError, OSError):
        return None
    except Exception as exc:
        warn(f"Unable to read HCLI gateway action: {exc}")
        return None

    action = str(raw_action).strip().lower()
    return action if action in _ACTIONS else None


def consume_gateway_action(
    *,
    info: LogFn = _noop,
    warn: LogFn = _noop,
    error: LogFn = _noop,
) -> tuple[str, dict[str, Any]] | None:
    """Consume one pending HCLI gateway action, resetting it to idle first."""
    try:
        import ida_settings  # type: ignore
    except (ImportError, ModuleNotFoundError):
        return None

    try:
        raw_action = ida_settings.get_current_plugin_setting(_ACTION_KEY)
    except (KeyError, RuntimeError, ValueError, OSError):
        return None
    except Exception as exc:
        warn(f"Unable to read HCLI gateway action: {exc}")
        return None

    action = str(raw_action).strip().lower()
    if not action or action == _IDLE:
        return None
    if action not in _ACTIONS:
        warn(f"Ignoring unsupported HCLI gateway action: {action}")
        try:
            ida_settings.set_current_plugin_setting(_ACTION_KEY, _IDLE)
        except Exception:
            pass
        return None

    # Claim the action before performing network/process work, so the watcher
    # does not repeat it if execution takes longer than the polling interval.
    try:
        ida_settings.set_current_plugin_setting(_ACTION_KEY, _IDLE)
    except Exception as exc:
        error(f"Unable to claim HCLI gateway action {action}: {exc}")
        return None

    from . import control

    info(f"Executing HCLI gateway action: {action}")
    if action == "start":
        result = control.ensure_gateway_running()
    elif action == "stop":
        result = control.shutdown_gateway(force=True)
    else:
        result = control.restart_gateway(force=True)

    if isinstance(result.get("error"), dict):
        error(f"HCLI gateway action {action} failed: {result['error']}")
    else:
        info(f"HCLI gateway action completed: {action}")
    return action, result


def start_gateway_action_watcher(
    *,
    info: LogFn = _noop,
    warn: LogFn = _noop,
    error: LogFn = _noop,
    poll_interval: float = _POLL_INTERVAL,
) -> None:
    """Start the IDA-side watcher for HCLI config gateway actions."""
    global _watcher_thread
    if _watcher_thread is not None and _watcher_thread.is_alive():
        return

    _stop_event.clear()

    def worker() -> None:
        while not _stop_event.wait(max(float(poll_interval), 0.1)):
            try:
                consume_gateway_action(info=info, warn=warn, error=error)
            except Exception as exc:  # pragma: no cover - defensive thread boundary
                error(f"HCLI gateway action watcher failed: {exc}")

    _watcher_thread = threading.Thread(
        target=worker,
        name="IDA-MCP-HCLI-GatewayActions",
        daemon=True,
    )
    _watcher_thread.start()


def stop_gateway_action_watcher(timeout: float = 2.0) -> None:
    global _watcher_thread
    _stop_event.set()
    thread = _watcher_thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=max(float(timeout), 0.0))
    _watcher_thread = None
