"""Unit tests for headless launch readiness matching (GitHub issue #20).

On Windows a venv ``Scripts\\python.exe`` is a redirector: the process that
runs ``ida_mcp.worker`` (and registers itself) is a child with a different
pid. These tests pin the registry-matching contract that must not depend on
pid equality alone.
"""

from __future__ import annotations

import threading

import pytest

from ida_mcp import bridge_client, instances, lifecycle


class _FakeClock:
    """Monotonic-ish clock so timeout paths never actually sleep."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


@pytest.fixture
def fake_clock(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(lifecycle.time, "monotonic", clock)
    monkeypatch.setattr(lifecycle, "_ATTACH_POLL_INTERVAL", 0.0)
    return clock


def _registry_entry(**overrides):
    entry = {
        "instance_id": "i-abc123",
        "pid": 31372,
        "port": 13400,
        "host": "127.0.0.1",
        "input_file": "G:\\sample.exe",
        "database_path": "G:\\sample.exe.i64",
        "headless": True,
        "started_at": 1.0,
    }
    entry.update(overrides)
    return entry


def test_wait_matches_by_port_when_registered_pid_differs(fake_clock, monkeypatch):
    """Issue #20: venv redirector spawns the real interpreter as a child, so
    the registered pid never equals Popen's pid. The reserved bridge port
    must be accepted as the readiness signal."""
    entry = _registry_entry()
    monkeypatch.setattr(instances, "read_instances", lambda: [entry])
    monkeypatch.setattr(bridge_client, "is_alive", lambda _entry: True)

    found = lifecycle._wait_for_instance(
        pid=19844, match_path=None, timeout=5.0, port=13400
    )

    assert found is entry


def test_wait_matches_by_pid_when_port_differs(fake_clock, monkeypatch):
    entry = _registry_entry(port=13455)
    monkeypatch.setattr(instances, "read_instances", lambda: [entry])
    monkeypatch.setattr(bridge_client, "is_alive", lambda _entry: True)

    found = lifecycle._wait_for_instance(
        pid=31372, match_path=None, timeout=5.0, port=13400
    )

    assert found is entry


def test_wait_times_out_without_a_match(fake_clock, monkeypatch):
    monkeypatch.setattr(instances, "read_instances", lambda: [_registry_entry()])
    monkeypatch.setattr(bridge_client, "is_alive", lambda _entry: True)

    found = lifecycle._wait_for_instance(
        pid=19844, match_path=None, timeout=5.0, port=13499
    )

    assert found is None


def test_wait_ignores_dead_bridge_on_port_match(fake_clock, monkeypatch):
    """A port-matching entry that never answers must not be returned."""
    entry = _registry_entry()
    monkeypatch.setattr(instances, "read_instances", lambda: [entry])
    monkeypatch.setattr(bridge_client, "is_alive", lambda _entry: False)

    found = lifecycle._wait_for_instance(
        pid=None, match_path=None, timeout=5.0, port=13400
    )

    assert found is None


def test_managed_workers_are_keyed_by_instance_id(monkeypatch):
    """close_database must find the spawned process via instance_id; the
    registry pid (redirector child) and Popen pid can differ."""
    registry_entry = _registry_entry(headless=False)  # e.g. a GUI launch
    spawned_pid = 19844  # ≠ registry_entry["pid"]

    class _StubProcess:
        def __init__(self) -> None:
            self.terminated = threading.Event()

        def poll(self):
            return None

        def wait(self, timeout=None):
            self.terminated.set()
            return 0

    proc = _StubProcess()
    with lifecycle._MANAGED_LOCK:
        lifecycle._MANAGED.clear()
        lifecycle._MANAGED["i-abc123"] = {
            "instance_id": "i-abc123",
            "headless": False,
            "spawned_at": 0.0,
            "process": proc,
        }

    monkeypatch.setattr(
        bridge_client, "request_shutdown", lambda entry, save: None
    )
    monkeypatch.setattr(instances, "remove_instance", lambda _iid: None)

    result = lifecycle.close_database(registry_entry, terminate=True, save=False)

    assert result["status"] == "closed"
    with lifecycle._MANAGED_LOCK:
        assert lifecycle._MANAGED.get("i-abc123") is None
        assert not lifecycle._MANAGED
    assert proc.terminated.is_set()
