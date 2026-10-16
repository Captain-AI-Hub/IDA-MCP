"""Unit tests for the shared JSON instance registry (no live IDA)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ida_mcp import instances


@pytest.fixture(autouse=True)
def _isolated_state_dir(tmp_path, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setenv("IDA_MCP_STATE_DIR", str(state))
    yield state


def _entry(**overrides):
    base = {
        "instance_id": "i-test0001",
        "pid": os.getpid(),
        "port": 13400,
        "host": "127.0.0.1",
        "input_file": "/tmp/sample.exe",
        "database_path": "/tmp/sample.exe.i64",
        "headless": True,
        "started_at": 1.0,
    }
    base.update(overrides)
    return base


def test_add_and_read_roundtrip():
    instances.add_instance(_entry())
    entries = instances.read_instances()
    assert [e["instance_id"] for e in entries] == ["i-test0001"]
    assert entries[0]["input_file"] == "/tmp/sample.exe"


def test_read_prunes_dead_pids():
    instances.add_instance(_entry(instance_id="i-alive", pid=os.getpid()))
    instances.add_instance(_entry(instance_id="i-dead", pid=999999999))
    entries = instances.read_instances()
    assert [e["instance_id"] for e in entries] == ["i-alive"]


def test_add_replaces_same_pid():
    instances.add_instance(_entry())
    instances.add_instance(_entry(input_file="/tmp/other.exe"))
    entries = instances.read_instances()
    assert len(entries) == 1
    assert entries[0]["input_file"] == "/tmp/other.exe"


def test_remove_instance():
    instances.add_instance(_entry())
    instances.remove_instance("i-test0001")
    assert instances.read_instances() == []


def test_find_by_path_matches_input_and_database(tmp_path):
    binary = tmp_path / "app.exe"
    binary.write_bytes(b"MZ")
    database = tmp_path / "app.exe.i64"
    database.write_bytes(b"IDB")
    instances.add_instance(
        _entry(input_file=str(binary), database_path=str(database))
    )
    assert instances.find_by_path(str(binary))["instance_id"] == "i-test0001"
    assert instances.find_by_path(str(binary) + ".i64")["instance_id"] == "i-test0001"
    assert instances.find_by_path("/tmp/missing.exe") is None


def test_touch_updates_last_seen():
    instances.add_instance(_entry())
    before = instances.read_instances()[0]["last_seen_at"]
    instances.touch_instance("i-test0001")
    after = instances.read_instances()[0]["last_seen_at"]
    assert after >= before


def test_pid_alive_self_and_missing():
    assert instances.pid_alive(os.getpid()) is True
    assert instances.pid_alive(999999999) is False
    assert instances.pid_alive(0) is False


def test_state_dir_respects_env(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_STATE_DIR", str(tmp_path / "custom"))
    assert instances.get_instances_path() == tmp_path / "custom" / "instances.json"


def test_lease_add_remove_holders():
    import os as _os

    iid = "i-lease-test"
    assert instances.lease_holders(iid) == []
    instances.lease_add(iid, _os.getpid())
    instances.lease_add(iid, 999999999)  # dead pid is pruned
    assert instances.lease_holders(iid) == [_os.getpid()]
    instances.lease_remove(iid, 424242)  # unknown pid changes nothing
    assert instances.lease_holders(iid) == [_os.getpid()]
    instances.lease_remove(iid, _os.getpid())
    assert instances.lease_holders(iid) == []
