from __future__ import annotations

import json

import pytest

import command


pytestmark = pytest.mark.lifecycle


class TestCommandCli:
    def test_gateway_start_uses_control_layer(self, monkeypatch, capsys):
        seen: dict[str, object] = {}

        def fake_ensure(startup_timeout: float = 3.0):
            seen["timeout"] = startup_timeout
            return {
                "gateway": {"alive": True},
                "proxy": {"alive": True},
                "instances": [],
                "count": 0,
                "coordinator": {"host": "127.0.0.1", "port": 11338},
                "http_proxy": {"host": "127.0.0.1", "port": 11338, "path": "/mcp"},
            }

        monkeypatch.setattr(command.control, "ensure_gateway_running", fake_ensure)

        exit_code = command.main(["gateway", "start", "--timeout", "5"])

        captured = capsys.readouterr()
        assert exit_code == 0
        assert seen["timeout"] == 5.0
        assert "Gateway: running" in captured.out

    def test_gateway_stop_passes_force_flag(self, monkeypatch, capsys):
        seen: dict[str, object] = {}

        def fake_shutdown(force: bool = False, timeout=None):
            seen["force"] = force
            seen["timeout"] = timeout
            return {"status": "ok", "message": "Gateway shutdown requested"}

        monkeypatch.setattr(command.control, "shutdown_gateway", fake_shutdown)

        exit_code = command.main(["gateway", "stop", "--force", "--timeout", "7"])

        captured = capsys.readouterr()
        assert exit_code == 0
        assert seen == {"force": True, "timeout": 7.0}
        assert "Gateway shutdown requested" in captured.out

    def test_gateway_status_json_reports_instances(self, monkeypatch, capsys):
        monkeypatch.setattr(
            command.control,
            "gateway_status_payload",
            lambda: {
                "gateway": {"alive": True, "log": "gateway.log"},
                "proxy": {"alive": True, "enabled": True},
                "instances": [{"pid": 123, "port": 10000, "input_file": "a.exe"}],
                "count": 1,
                "coordinator": {"host": "127.0.0.1", "port": 11338},
                "http_proxy": {"host": "127.0.0.1", "port": 11338, "path": "/mcp"},
            },
        )

        exit_code = command.main(["gateway", "status", "--json"])

        payload = json.loads(capsys.readouterr().out)
        assert exit_code == 0
        assert payload["count"] == 1
        assert payload["instances"][0]["pid"] == 123
        assert payload["gateway"]["alive"] is True

    def test_instances_list_does_not_query_when_gateway_stopped(self, monkeypatch, capsys):
        monkeypatch.setattr(
            command.control,
            "list_ida_instances",
            lambda: {"gateway_alive": False, "count": 0, "instances": []},
        )

        exit_code = command.main(["instances", "list"])

        captured = capsys.readouterr()
        assert exit_code == 0
        assert "Gateway is not running." in captured.out

    def test_ida_select_json_reports_selected_port(self, monkeypatch, capsys):
        monkeypatch.setattr(
            command.control,
            "select_target_port",
            lambda port=None: {
                "selected_port": 10000,
                "instance": {"pid": 123, "port": 10000, "input_file": "sample.exe"},
            },
        )

        exit_code = command.main(["ida", "select", "--json"])

        payload = json.loads(capsys.readouterr().out)
        assert exit_code == 0
        assert payload["selected_port"] == 10000

    def test_tool_call_rejects_non_object_json(self, capsys):
        exit_code = command.main(["tool", "call", "get_metadata", "--params", "[]"])

        payload = json.loads(capsys.readouterr().out)
        assert exit_code == command.EXIT_USAGE
        assert payload["error"]["code"] == "invalid_json"

    def test_resource_read_uses_control_layer(self, monkeypatch, capsys):
        monkeypatch.setattr(
            command.control,
            "read_resource",
            lambda uri, port=None, timeout=None: {
                "uri": uri,
                "selected_port": 10000,
                "data": {"kind": "functions", "count": 0, "items": []},
            },
        )

        exit_code = command.main(["resource", "read", "ida://functions", "--json"])

        payload = json.loads(capsys.readouterr().out)
        assert exit_code == 0
        assert payload["uri"] == "ida://functions"
        assert payload["data"]["kind"] == "functions"
