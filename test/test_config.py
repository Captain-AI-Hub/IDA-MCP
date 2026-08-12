"""Unit tests for HCLI-backed configuration."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import patch

from ida_mcp import config


def _reset_config_cache() -> None:
    config._cached_config = None


def test_hcli_settings_override_config_file_and_environment():
    values = {
        "gateway_token": "hcli-token-with-sufficient-length",
        "auto_start": True,
        "enable_unsafe": False,
        "http_port": "12345",
    }
    fake_ida_settings = SimpleNamespace(
        get_current_plugin_setting=lambda key: values.get(key, "")
    )

    with patch.dict(sys.modules, {"ida_settings": fake_ida_settings}):
        with patch.object(
            config,
            "parse_config_file",
            return_value={"gateway_token": "file-token", "auto_start": False},
        ):
            with patch.dict(
                config.os.environ,
                {"IDA_MCP_CONFIG_GATEWAY_TOKEN": "environment-token"},
                clear=False,
            ):
                loaded = config.load_config(reload=True)

    assert loaded["gateway_token"] == "hcli-token-with-sufficient-length"
    assert loaded["auto_start"] is True
    assert loaded["enable_unsafe"] is False
    assert loaded["http_port"] == "12345"
    _reset_config_cache()


def test_empty_optional_hcli_setting_preserves_config_file_value():
    fake_ida_settings = SimpleNamespace(
        get_current_plugin_setting=lambda _key: ""
    )

    with patch.dict(sys.modules, {"ida_settings": fake_ida_settings}):
        with patch.object(
            config,
            "parse_config_file",
            return_value={"ida_path": r"C:\Program Files\IDA Professional 9.4\ida.exe"},
        ):
            loaded = config.load_config(reload=True)

    assert loaded["ida_path"] == r"C:\Program Files\IDA Professional 9.4\ida.exe"
    _reset_config_cache()


def test_build_subprocess_environment_forwards_effective_settings():
    with patch.object(
        config,
        "load_config",
        return_value={
            "gateway_token": "gateway-token",
            "auto_start": True,
            "enable_unsafe": False,
            "ida_path": "",
        },
    ):
        environment = config.build_subprocess_environment({"PATH": "test-path"})

    assert environment["PATH"] == "test-path"
    assert environment["IDA_MCP_CONFIG_GATEWAY_TOKEN"] == "gateway-token"
    assert environment["IDA_MCP_CONFIG_AUTO_START"] == "true"
    assert environment["IDA_MCP_CONFIG_ENABLE_UNSAFE"] == "false"
    assert "IDA_MCP_CONFIG_IDA_PATH" not in environment


def test_initialize_runtime_settings_generates_token_and_detects_python():
    with patch.object(
        config,
        "load_config",
        return_value={
            "gateway_token": config._AUTO_TOKEN_SENTINEL,
            "ida_python": "auto",
        },
    ):
        with patch.object(config.secrets, "token_urlsafe", return_value="generated-token-with-enough-entropy"):
            with patch.object(
                config,
                "_detect_running_ida_python",
                return_value=r"C:\Python312\python.exe",
            ):
                with patch.object(config, "_persist_string_setting", return_value=True) as persist:
                    result = config.initialize_runtime_settings()

    assert result == {
        "gateway_token": "generated-token-with-enough-entropy",
        "gateway_token_generated": True,
        "ida_python": r"C:\Python312\python.exe",
        "ida_python_detected": True,
    }
    assert persist.call_args_list[0].args == (
        "gateway_token",
        "generated-token-with-enough-entropy",
    )
    assert persist.call_args_list[1].args == (
        "ida_python",
        r"C:\Python312\python.exe",
    )
    _reset_config_cache()


def test_get_ida_python_treats_auto_as_unconfigured():
    with patch.object(config, "load_config", return_value={"ida_python": "auto"}):
        assert config.get_ida_python() is None


def test_get_mcp_client_config_includes_url_and_token_headers():
    with patch.object(config, "get_http_url", return_value="http://127.0.0.1:11338/mcp"):
        with patch.object(config, "get_gateway_token", return_value="secret-token"):
            value = config.get_mcp_client_config()

    assert value == {
        "mcpServers": {
            "ida-mcp": {
                "url": "http://127.0.0.1:11338/mcp",
                "headers": {
                    "Authorization": "Bearer secret-token",
                    "X-IDA-MCP-Token": "secret-token",
                },
            }
        }
    }


def test_initialize_runtime_settings_reports_generated_token_when_persistence_fails():
    with patch.object(
        config,
        "load_config",
        return_value={"gateway_token": config._AUTO_TOKEN_SENTINEL, "ida_python": "auto"},
    ):
        with patch.object(config.secrets, "token_urlsafe", return_value="generated-token-with-enough-entropy"):
            with patch.object(config, "_detect_running_ida_python", return_value=None):
                with patch.object(config, "_persist_string_setting", return_value=False):
                    result = config.initialize_runtime_settings()

    assert result["gateway_token"] == "generated-token-with-enough-entropy"
    assert result["gateway_token_generated"] is True
    assert config._cached_config["gateway_token"] == "generated-token-with-enough-entropy"
    _reset_config_cache()
