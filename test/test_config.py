"""Config layer tests: precedence, user config, env overrides, accessors."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ida_mcp import config


@pytest.fixture(autouse=True)
def _reload_config():
    config._cached_config = None
    yield
    config._cached_config = None


def test_defaults_apply_without_overrides():
    with patch.object(config, "_hcli_setting_overrides", return_value={}):
        loaded = config.load_config(reload=True)
    assert loaded["request_timeout"] == 30


def test_env_overrides_beat_file_config(monkeypatch):
    monkeypatch.setenv("IDA_MCP_CONFIG_REQUEST_TIMEOUT", "77")
    with patch.object(config, "_hcli_setting_overrides", return_value={}):
        loaded = config.load_config(reload=True)
    assert loaded["request_timeout"] == 77


def test_hcli_settings_beat_env(monkeypatch):
    monkeypatch.setenv("IDA_MCP_CONFIG_REQUEST_TIMEOUT", "11")
    with patch.object(
        config,
        "_hcli_setting_overrides",
        return_value={"request_timeout": 22},
    ):
        loaded = config.load_config(reload=True)
    assert loaded["request_timeout"] == 22


def test_accessors(tmp_path):
    with patch.object(config, "_user_config_file", return_value=str(tmp_path / "none.conf")):
        with patch.object(config, "_hcli_setting_overrides", return_value={}):
            assert config.get_ida_path() is None
        assert config.get_idalib_python() is None
        assert config.get_request_timeout() == 30
        assert config.is_debug_enabled() is False
    # Removed layers stay removed: http transport, gateway token, unsafe
    # gating, WSL bridge, and the bridge host/port/token/auto_start knobs.
    for name in (
        "get_transport",
        "get_http_url",
        "get_gateway_token",
        "is_unsafe_enabled",
        "is_wsl_path_bridge_enabled",
        "get_instance_host",
        "get_instance_port",
        "get_instance_token",
        "is_auto_start_enabled",
        "is_open_in_ida_autonomous_enabled",
        "get_server_name",
        "get_launch_bundle_dir",
    ):
        assert not hasattr(config, name), name


def test_persist_user_setting_roundtrip(tmp_path):
    user_conf = tmp_path / "config.conf"
    with patch.object(config, "_user_config_file", return_value=str(user_conf)):
        assert config.persist_user_setting("idalib_python", "/opt/idapy/bin/python3.12")
        content = user_conf.read_text(encoding="utf-8")
        assert 'idalib_python = "/opt/idapy/bin/python3.12"' in content
        with patch.object(config, "_hcli_setting_overrides", return_value={}):
            loaded = config.load_config(reload=True)
    assert loaded["idalib_python"] == "/opt/idapy/bin/python3.12"


def test_initialize_runtime_settings_detects_python(tmp_path):
    with patch.object(config, "_CONFIG_FILE", str(tmp_path / "none.conf")):
        with patch.object(
            config, "_user_config_file", return_value=str(tmp_path / "user.conf")
        ):
            with patch.object(
                config,
                "_detect_running_ida_python",
                return_value="/opt/idapy/bin/python3.12",
            ):
                with patch.object(
                    config, "_write_config_string", return_value=True
                ) as write:
                    result = config.initialize_runtime_settings()
    assert result["ida_python"] == "/opt/idapy/bin/python3.12"
    assert result["ida_python_detected"] is True
    write.assert_called_once()
