"""Tests for HCLI config-driven gateway lifecycle actions."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import patch

from ida_mcp import hcli_gateway_actions as actions


def _fake_settings(initial: str):
    state = {"gateway": initial}

    def get_setting(key: str):
        return state[key]

    def set_setting(key: str, value):
        state[key] = value

    return state, SimpleNamespace(
        get_current_plugin_setting=get_setting,
        set_current_plugin_setting=set_setting,
    )


def test_consume_gateway_start_resets_setting_before_execution():
    state, fake_settings = _fake_settings("start")

    def ensure_gateway_running():
        assert state["gateway"] == "idle"
        return {"ok": True}

    with patch.dict(sys.modules, {"ida_settings": fake_settings}):
        with patch.object(
            actions,
            "_watcher_thread",
            None,
        ):
            with patch("ida_mcp.control.ensure_gateway_running", ensure_gateway_running):
                consumed = actions.consume_gateway_action()

    assert consumed == ("start", {"ok": True})
    assert state["gateway"] == "idle"


def test_consume_gateway_stop_forces_shutdown():
    state, fake_settings = _fake_settings("stop")
    seen = {}

    def shutdown_gateway(force=False, timeout=None):
        seen.update(force=force, timeout=timeout)
        return {"status": "ok"}

    with patch.dict(sys.modules, {"ida_settings": fake_settings}):
        with patch("ida_mcp.control.shutdown_gateway", shutdown_gateway):
            consumed = actions.consume_gateway_action()

    assert consumed == ("stop", {"status": "ok"})
    assert seen == {"force": True, "timeout": None}
    assert state["gateway"] == "idle"


def test_consume_gateway_restart_forces_restart():
    state, fake_settings = _fake_settings("restart")
    seen = {}

    def restart_gateway(startup_timeout=None, force=False):
        seen.update(startup_timeout=startup_timeout, force=force)
        return {"requested": "restart"}

    with patch.dict(sys.modules, {"ida_settings": fake_settings}):
        with patch("ida_mcp.control.restart_gateway", restart_gateway):
            consumed = actions.consume_gateway_action()

    assert consumed == ("restart", {"requested": "restart"})
    assert seen == {"startup_timeout": None, "force": True}
    assert state["gateway"] == "idle"


def test_idle_gateway_action_does_nothing():
    state, fake_settings = _fake_settings("idle")
    with patch.dict(sys.modules, {"ida_settings": fake_settings}):
        assert actions.consume_gateway_action() is None
    assert state["gateway"] == "idle"


def test_get_pending_gateway_action_does_not_reset_setting():
    state, fake_settings = _fake_settings("restart")
    with patch.dict(sys.modules, {"ida_settings": fake_settings}):
        assert actions.get_pending_gateway_action() == "restart"
    assert state["gateway"] == "restart"
