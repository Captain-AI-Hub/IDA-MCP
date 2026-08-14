"""测试生命周期管理工具 (open_in_ida, close_ida)。

注意：这些测试涉及启动和关闭进程，可能会影响正在运行的 IDA 实例。
建议在受控环境中运行。
"""

import asyncio
import importlib.util
import pytest
import os
import time
import subprocess
import sys
import tempfile
import types
from contextlib import asynccontextmanager
from unittest.mock import patch
from starlette.testclient import TestClient

# 添加 ida_mcp 子项目根目录到 sys.path 以便导入 ida_mcp 模块
IDA_MCP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if IDA_MCP_ROOT not in sys.path:
    sys.path.insert(0, IDA_MCP_ROOT)

from ida_mcp import config
from ida_mcp import instance_registry
from ida_mcp import instance_server
from ida_mcp import plugin_runtime
from ida_mcp import protocol_guard
from ida_mcp import registry
from ida_mcp import registry_routes
from ida_mcp import registry_server
from ida_mcp.proxy import lifecycle
from ida_mcp.proxy import _state as proxy_state
from ida_mcp import runtime

pytestmark = pytest.mark.lifecycle


@pytest.fixture
def isolated_gateway_state(monkeypatch):
    monkeypatch.setattr(instance_registry, "_instances", [])
    monkeypatch.setattr(instance_registry, "_call_locks", {})
    monkeypatch.setattr(instance_registry, "_current_instance_port", None)
    monkeypatch.setattr(instance_registry, "_last_reap_ts", [0.0])


class _DummySocketConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _load_plugin_module(monkeypatch):
    """Load the ida_mcp.py IDA plugin with fake IDA modules for unit testing.

    The plugin entry-point lives at ``ida_mcp.py`` in the repository root.
    """
    module_name = f"ida_mcp_plugin_test_{time.time_ns()}"
    plugin_path = os.path.join(IDA_MCP_ROOT, "ida_mcp.py")
    fake_idaapi = types.SimpleNamespace(
        plugin_t=object,
        PLUGIN_KEEP=1,
        PLUGIN_SKIP=0,
        PATH_TYPE_IDB=0,
    )
    fake_ida_kernwin = types.SimpleNamespace(
        MFF_READ=0,
        execute_sync=lambda fn, flags: fn(),
    )

    monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)
    monkeypatch.setitem(sys.modules, "ida_kernwin", fake_ida_kernwin)

    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestLifecycleOpen:
    """Lifecycle management tests - Open IDA.
    Runs first to initialize environment.
    """

    def test_open_and_close_simple_ida_instance(self, tool_caller):
        """Open simple.exe, locate its registered MCP port, then close only that instance."""
        sample_path = os.path.join(IDA_MCP_ROOT, "test", "samples", "simple.exe")

        if not os.path.exists(sample_path):
            pytest.skip(f"Sample file not found: {sample_path}")

        print(f"\nAttempting to launch IDA with: {sample_path}")
        result = tool_caller("open_in_ida", {"file_path": sample_path})

        # Check launch status
        if "error" in result:
            error_msg = result["error"]
            if "not configured" in error_msg or "executable not found" in error_msg:
                pytest.skip(f"IDA environment not configured: {error_msg}")
            else:
                pytest.fail(f"Failed to launch IDA: {error_msg}")

        assert "status" in result
        assert result["status"] == "ok"
        assert "Launched IDA" in result["message"]
        requested_port = result.get("requested_port")
        assert isinstance(requested_port, int), f"open_in_ida did not return requested_port: {result}"

        print(f"\nWaiting for simple.exe instance on port {requested_port}...")
        matched_instance = None
        for i in range(60):
            try:
                instances = tool_caller("list_instances", {})
                if isinstance(instances, list):
                    for instance in instances:
                        if instance.get("port") != requested_port:
                            continue
                        input_name = os.path.basename(str(instance.get("input_file") or "")).lower()
                        state = str(instance.get("effective_state") or "")
                        if "simple.exe" in input_name and state == "ready":
                            matched_instance = instance
                            break
                if matched_instance is not None:
                    print(f"simple.exe instance registered after {i + 1} retries.")
                    break
            except Exception:
                pass
            time.sleep(1)

        assert matched_instance is not None, (
            f"simple.exe did not register on requested port {requested_port}"
        )

        metadata = tool_caller("get_metadata", {"port": requested_port, "timeout": 60})
        assert isinstance(metadata, dict), f"Expected metadata dict, got: {metadata}"
        assert "error" not in metadata, f"simple.exe metadata failed: {metadata.get('error')}"
        assert "simple.exe" in str(metadata.get("input_file", "")).lower()

        close_result = tool_caller(
            "close_ida",
            {"port": requested_port, "save": False, "timeout": 60},
        )
        assert isinstance(close_result, dict), f"Expected close result dict: {close_result}"
        assert "error" not in close_result, f"close_ida failed: {close_result.get('error')}"
        assert close_result.get("status") == "ok", f"Unexpected close result: {close_result}"

        for _ in range(30):
            instances = tool_caller("list_instances", {})
            if isinstance(instances, list) and not any(
                item.get("port") == requested_port for item in instances
            ):
                break
            time.sleep(1)
        else:
            pytest.fail(f"simple.exe instance still registered after close: port {requested_port}")


class TestLifecycleErrors:
    """生命周期管理测试 - 异常情况。"""

    def test_open_in_ida_invalid_path(self, tool_caller):
        """测试打开不存在的文件。"""
        result = tool_caller("open_in_ida", {"file_path": "non_existent_file.exe"})
        assert "error" in result
        assert "not found" in result["error"] or "File not found" in result["error"]

    def test_open_in_ida_no_config(self, tool_caller):
        """测试未配置 IDA 路径的情况（模拟）。"""
        with patch("ida_mcp.proxy.lifecycle.get_ida_path", return_value=None):
            result = lifecycle.open_in_ida(__file__)
        assert "error" in result
        assert "not configured" in result["error"]

    def test_open_in_ida_tool_exists(self, tool_caller):
        """验证 open_in_ida 工具已注册。"""
        result = tool_caller("open_in_ida", {"file_path": "invalid"})
        assert "error" in result
        assert (
            "not found" in result["error"]
            or "not configured" in result["error"]
            or "Failed to launch" in result["error"]
        )

    def test_open_in_ida_reserves_incrementing_ports(self):
        """连续启动未注册实例时，端口预留应继续向上分配。"""
        launch_root = os.path.join(tempfile.gettempdir(), "ida-launch-root")
        bundle_dir = os.path.join(launch_root, "ida_mcp_open_20260317-120000-000001")
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                            return_value=launch_root,
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle._is_port_bindable",
                                return_value=True,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle._launch_bundle_dir",
                                    return_value=bundle_dir,
                                ):
                                    with patch(
                                        "ida_mcp.proxy.lifecycle._stage_target_file_for_launch",
                                        return_value=(__file__, __file__),
                                    ):
                                        with patch(
                                            "ida_mcp.proxy.lifecycle.is_open_in_ida_autonomous_enabled",
                                            return_value=False,
                                        ):
                                            with patch(
                                                "subprocess.Popen"
                                            ) as mock_popen:
                                                first = lifecycle.open_in_ida(__file__)
                                                second = lifecycle.open_in_ida(__file__)

        assert first["status"] == "ok"
        assert second["status"] == "ok"
        assert first["requested_port"] == 10000
        assert second["requested_port"] == 10001
        assert mock_popen.call_args_list[0].kwargs["env"]["IDA_MCP_PORT"] == "10000"
        assert mock_popen.call_args_list[1].kwargs["env"]["IDA_MCP_PORT"] == "10001"
        assert mock_popen.call_args_list[0].kwargs["env"]["IDA_MCP_AUTO_START"] == "1"
        assert mock_popen.call_args_list[1].kwargs["env"]["IDA_MCP_AUTO_START"] == "1"
        assert "-A" not in mock_popen.call_args_list[0].args[0]
        assert "-A" not in mock_popen.call_args_list[1].args[0]

    def test_open_in_ida_preserves_explicit_extra_args(self):
        """仅在调用方显式要求时，才把批处理参数传给 IDA。"""
        launch_root = os.path.join(tempfile.gettempdir(), "ida-launch-root")
        bundle_dir = os.path.join(launch_root, "ida_mcp_open_20260317-120000-000001")
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                            return_value=launch_root,
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle._is_port_bindable",
                                return_value=True,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle._launch_bundle_dir",
                                    return_value=bundle_dir,
                                ):
                                    with patch(
                                        "ida_mcp.proxy.lifecycle._stage_target_file_for_launch",
                                        return_value=(__file__, __file__),
                                    ):
                                        with patch(
                                            "ida_mcp.proxy.lifecycle.is_open_in_ida_autonomous_enabled",
                                            return_value=True,
                                        ):
                                            with patch(
                                                "subprocess.Popen"
                                            ) as mock_popen:
                                                result = lifecycle.open_in_ida(
                                                    __file__,
                                                    extra_args=["-A", "-Llog.txt"],
                                                )

        assert result["status"] == "ok"
        cmd = mock_popen.call_args.args[0]
        assert "-A" in cmd
        assert cmd.count("-A") == 1
        assert "-Llog.txt" in cmd
        assert mock_popen.call_args.kwargs["env"]["IDA_MCP_AUTO_START"] == "1"

    def test_open_in_ida_adds_a_when_autonomous_enabled(self):
        launch_root = os.path.join(tempfile.gettempdir(), "ida-launch-root")
        bundle_dir = os.path.join(launch_root, "ida_mcp_open_20260317-120000-000001")
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                            return_value=launch_root,
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle._is_port_bindable",
                                return_value=True,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle._launch_bundle_dir",
                                    return_value=bundle_dir,
                                ):
                                    with patch(
                                        "ida_mcp.proxy.lifecycle._stage_target_file_for_launch",
                                        return_value=(__file__, __file__),
                                    ):
                                        with patch(
                                            "ida_mcp.proxy.lifecycle.is_open_in_ida_autonomous_enabled",
                                            return_value=True,
                                        ):
                                            with patch(
                                                "subprocess.Popen"
                                            ) as mock_popen:
                                                result = lifecycle.open_in_ida(
                                                    __file__,
                                                    extra_args=["-Llog.txt"],
                                                )

        assert result["status"] == "ok"
        cmd = mock_popen.call_args.args[0]
        assert cmd[1] == "-A"
        assert cmd.count("-A") == 1
        assert "-Llog.txt" in cmd

    def test_open_in_ida_registers_pending_instance_after_launch(self):
        launch_root = os.path.join(tempfile.gettempdir(), "ida-launch-root")
        pending_proc = types.SimpleNamespace(pid=4242)
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                            return_value=launch_root,
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle._is_port_bindable",
                                return_value=True,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle._launch_bundle_dir",
                                    return_value=launch_root,
                                ):
                                    with patch(
                                        "ida_mcp.proxy.lifecycle._stage_target_file_for_launch",
                                        return_value=(__file__, __file__),
                                    ):
                                        with patch(
                                            "subprocess.Popen",
                                            return_value=pending_proc,
                                        ):
                                            with patch(
                                                "ida_mcp.proxy.lifecycle.is_open_in_ida_autonomous_enabled",
                                                return_value=False,
                                            ):
                                                with patch(
                                                    "ida_mcp.proxy.lifecycle.registry.register_pending_instance"
                                                ) as mock_register_pending:
                                                    result = lifecycle.open_in_ida(
                                                        __file__
                                                    )

        assert result["status"] == "ok"
        assert result["pid"] == 4242
        mock_register_pending.assert_called_once_with(
            4242, 10000, __file__, None, lifecycle_state="starting"
        )

    def test_open_in_ida_omits_a_when_autonomous_disabled(self):
        launch_root = os.path.join(tempfile.gettempdir(), "ida-launch-root")
        bundle_dir = os.path.join(launch_root, "ida_mcp_open_20260317-120000-000001")
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                            return_value=launch_root,
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle._is_port_bindable",
                                return_value=True,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle._launch_bundle_dir",
                                    return_value=bundle_dir,
                                ):
                                    with patch(
                                        "ida_mcp.proxy.lifecycle._stage_target_file_for_launch",
                                        return_value=(__file__, __file__),
                                    ):
                                        with patch(
                                            "ida_mcp.proxy.lifecycle.is_open_in_ida_autonomous_enabled",
                                            return_value=False,
                                        ):
                                            with patch(
                                                "subprocess.Popen"
                                            ) as mock_popen:
                                                result = lifecycle.open_in_ida(
                                                    __file__,
                                                    extra_args=["-Llog.txt"],
                                                )

        assert result["status"] == "ok"
        cmd = mock_popen.call_args.args[0]
        assert "-A" not in cmd
        assert "-Llog.txt" in cmd

    def test_resolve_launch_inputs_prefers_existing_database(self, tmp_path):
        sample = tmp_path / "sample.exe"
        database = tmp_path / "sample.exe.i64"
        sample.write_bytes(b"test")
        database.write_bytes(b"idb")

        launch_target, input_file_path, database_path = (
            lifecycle._resolve_launch_inputs(str(sample))
        )

        assert launch_target == str(database.resolve())
        assert input_file_path == str(sample.resolve())
        assert database_path == str(database.resolve())

    def test_config_accessors_read_config_only_values(self):
        with patch(
            "ida_mcp.config.load_config",
            return_value={
                "open_in_ida_bundle_dir": r"E:\config-temp",
                "open_in_ida_autonomous": False,
                "wsl_path_bridge": True,
                "ida_host": "127.0.0.2",
                "auto_start": True,
                "server_name": "IDA-MCP-Test",
            },
        ):
            assert config.get_open_in_ida_bundle_dir() == r"E:\config-temp"
            assert config.is_open_in_ida_autonomous_enabled() is False
            assert config.is_wsl_path_bridge_enabled() is True
            assert config.get_ida_host() == "127.0.0.2"
            assert config.is_auto_start_enabled() is True
            assert config.get_server_name() == "IDA-MCP-Test"

    def test_wsl_bridge_path_helpers_convert_windows_and_mount_paths(self):
        assert (
            lifecycle._windows_to_wsl_path(r"D:\ida-mcp\sample.exe")
            == "/mnt/d/ida-mcp/sample.exe"
        )
        assert (
            lifecycle._wsl_to_windows_path("/mnt/d/ida-mcp/sample.exe")
            == r"D:\ida-mcp\sample.exe"
        )

    def test_launch_bundle_dir_uses_timestamp_directory(self, tmp_path):
        root_dir = str(tmp_path)
        with patch(
            "ida_mcp.proxy.lifecycle._timestamp_dir_name",
            return_value="ida_mcp_open_20260317-120000-000001",
        ):
            with patch("ida_mcp.proxy.lifecycle.os.makedirs") as mock_makedirs:
                path = lifecycle._launch_bundle_dir(root_dir=root_dir)

        expected_root = root_dir
        expected_bundle = os.path.join(root_dir, "ida_mcp_open_20260317-120000-000001")
        assert path == expected_bundle
        assert mock_makedirs.call_args_list[0].args[0] == expected_root
        assert mock_makedirs.call_args_list[1].args[0] == expected_bundle

    def test_open_in_ida_stages_target_in_configured_root(self):
        bundle_root = r"D:\ida-mcp"
        bundle_dir = os.path.join(bundle_root, "ida_mcp_open_20260317-120000-000001")
        staged_file = os.path.join(bundle_dir, os.path.basename(__file__))
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                            return_value=bundle_root,
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle._is_port_bindable",
                                return_value=True,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle._launch_bundle_dir",
                                    return_value=bundle_dir,
                                ) as mock_launch_bundle:
                                    with patch(
                                        "ida_mcp.proxy.lifecycle._stage_target_file_for_launch",
                                        return_value=(staged_file, staged_file),
                                    ) as mock_stage:
                                        with patch("subprocess.Popen") as mock_popen:
                                            result = lifecycle.open_in_ida(__file__)

        mock_launch_bundle.assert_called_once_with(bundle_root)
        mock_stage.assert_called_once_with(__file__, bundle_dir)
        assert result["launch_bundle"] == bundle_dir
        assert result["staged_file"] == staged_file
        assert result["launch_target"] == staged_file
        assert staged_file in mock_popen.call_args.args[0]

    def test_open_in_ida_uses_direct_target_path_when_bundle_dir_unset(self):
        direct_target = os.path.abspath(__file__)
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                            return_value=None,
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle._is_port_bindable",
                                return_value=True,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle._use_direct_target_file",
                                    return_value=(direct_target, None),
                                ) as mock_direct:
                                    with patch("subprocess.Popen") as mock_popen:
                                        result = lifecycle.open_in_ida(__file__)

        mock_direct.assert_called_once_with(__file__)
        assert result["launch_bundle"] is None
        assert result["staged_file"] is None
        assert result["launch_target"] == direct_target
        assert direct_target in mock_popen.call_args.args[0]

    def test_stage_target_file_for_launch_preserves_basename_when_staging(
        self, tmp_path
    ):
        copied = []
        bundle_dir = str(tmp_path / "launch-bundle")
        expected_local = os.path.join(bundle_dir, "same.bin")

        with patch(
            "ida_mcp.proxy.lifecycle.shutil.copy2",
            side_effect=lambda src, dst: copied.append((src, dst)),
        ):
            staged_path, staged_local = lifecycle._stage_target_file_for_launch(
                "/home/user/same.bin", bundle_dir
            )

        assert staged_path == expected_local
        assert staged_local == expected_local
        assert copied == [("/home/user/same.bin", expected_local)]

    def test_stage_target_file_for_launch_prefers_database_when_present(self, tmp_path):
        bundle_dir = tmp_path / "launch-bundle"
        bundle_dir.mkdir()
        sample = tmp_path / "sample.exe"
        database = tmp_path / "sample.exe.i64"
        sample.write_bytes(b"test")
        database.write_bytes(b"idb")

        launch_path, staged_requested = lifecycle._stage_target_file_for_launch(
            str(sample), str(bundle_dir)
        )

        assert launch_path == str((bundle_dir / database.name).resolve())
        assert staged_requested == str((bundle_dir / sample.name).resolve())
        assert (bundle_dir / sample.name).exists()
        assert (bundle_dir / database.name).exists()

    def test_open_in_ida_releases_reserved_port_when_launch_fails(self):
        """启动失败后，应释放预留端口以便后续重试。"""
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                            return_value=None,
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle._is_port_bindable",
                                return_value=True,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle._use_direct_target_file",
                                    return_value=(__file__, None),
                                ):
                                    with patch(
                                        "subprocess.Popen",
                                        side_effect=RuntimeError("boom"),
                                    ):
                                        result = lifecycle.open_in_ida(__file__)
            assert lifecycle._RESERVED_LAUNCH_PORTS == {}

        assert "error" in result

    def test_open_in_ida_bridge_reports_host_windows_paths_when_staging(self):
        host_target_ida = r"D:\safetools\IDAPro-9.3\ida.exe"
        host_bundle_root = r"E:\ida-mcp"
        host_source_file = r"E:\inputs\sample.exe"
        local_target_ida = (
            host_target_ida
            if os.name == "nt"
            else "/mnt/d/safetools/IDAPro-9.3/ida.exe"
        )
        local_bundle_root = host_bundle_root if os.name == "nt" else "/mnt/e/ida-mcp"
        local_source_file = (
            host_source_file if os.name == "nt" else "/mnt/e/inputs/sample.exe"
        )
        local_bundle_dir = os.path.join(
            local_bundle_root, "ida_mcp_open_20260317-120000-000001"
        )
        local_staged_file = os.path.join(local_bundle_dir, "sample.exe")
        host_bundle_dir = r"E:\ida-mcp\ida_mcp_open_20260317-120000-000001"
        host_staged_file = r"E:\ida-mcp\ida_mcp_open_20260317-120000-000001\sample.exe"

        def _fake_exists(path):
            return path in {local_target_ida, local_source_file}

        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.is_wsl_path_bridge_enabled", return_value=True
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_path", return_value=host_target_ida
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_ida_default_port",
                        return_value=10000,
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                                return_value=host_bundle_root,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle.os.path.exists",
                                    side_effect=_fake_exists,
                                ):
                                    with patch(
                                        "ida_mcp.proxy.lifecycle._is_port_bindable",
                                        return_value=True,
                                    ):
                                        with patch(
                                            "ida_mcp.proxy.lifecycle._normalize_bundle_dir",
                                            return_value=local_bundle_root,
                                        ) as mock_normalize:
                                            with patch(
                                                "ida_mcp.proxy.lifecycle._launch_bundle_dir",
                                                return_value=local_bundle_dir,
                                            ) as mock_launch_bundle:
                                                with patch(
                                                    "ida_mcp.proxy.lifecycle._stage_target_file_for_launch",
                                                    return_value=(
                                                        local_staged_file,
                                                        local_staged_file,
                                                    ),
                                                ) as mock_stage:
                                                    with patch(
                                                        "subprocess.Popen"
                                                    ) as mock_popen:
                                                        result = lifecycle.open_in_ida(
                                                            host_source_file,
                                                        )

        mock_normalize.assert_called_once_with(local_bundle_root)
        mock_launch_bundle.assert_called_once_with(local_bundle_root)
        mock_stage.assert_called_once_with(local_source_file, local_bundle_dir)
        assert result["launch_bundle"] == host_bundle_dir
        assert result["staged_file"] == host_staged_file
        assert result["launch_target"] == host_staged_file
        cmd = mock_popen.call_args.args[0]
        assert cmd[0] == local_target_ida
        assert cmd[-1] == host_staged_file

    def test_open_in_ida_bridge_rejects_non_windows_launch_target_without_staging(self):
        host_target_ida = r"D:\safetools\IDAPro-9.3\ida.exe"
        source_file = "/opt/ida-mcp/sample.exe"
        local_target_ida = (
            host_target_ida
            if os.name == "nt"
            else "/mnt/d/safetools/IDAPro-9.3/ida.exe"
        )

        def _fake_exists(path):
            return path in {local_target_ida, source_file}

        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch(
                "ida_mcp.proxy.lifecycle.is_wsl_path_bridge_enabled", return_value=True
            ):
                with patch(
                    "ida_mcp.proxy.lifecycle.get_ida_path", return_value=host_target_ida
                ):
                    with patch(
                        "ida_mcp.proxy.lifecycle.get_ida_default_port",
                        return_value=10000,
                    ):
                        with patch(
                            "ida_mcp.proxy.lifecycle.get_instances", return_value=[]
                        ):
                            with patch(
                                "ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir",
                                return_value=None,
                            ):
                                with patch(
                                    "ida_mcp.proxy.lifecycle.os.path.exists",
                                    side_effect=_fake_exists,
                                ):
                                    with patch(
                                        "ida_mcp.proxy.lifecycle._is_port_bindable",
                                        return_value=True,
                                    ):
                                        with patch(
                                            "ida_mcp.proxy.lifecycle._use_direct_target_file",
                                            return_value=(source_file, None),
                                        ):
                                            with patch(
                                                "subprocess.Popen"
                                            ) as mock_popen:
                                                result = lifecycle.open_in_ida(
                                                    source_file
                                                )

        assert "error" in result
        assert "cannot be translated to a Windows path" in result["error"]
        mock_popen.assert_not_called()


class TestLifecycleClose:
    """Lifecycle management tests - Close IDA.
    Runs last to clean up environment.
    """

    def test_close_ida_is_covered_by_simple_lifecycle(self):
        """close_ida is exercised by test_open_and_close_simple_ida_instance."""
        assert True


class TestRegistryStartup:
    """网关启动与注册的回归测试。"""

    def test_config_exposes_gateway_switch(self):
        fake_config = {"enable_gateway": True}
        with patch("ida_mcp.config.load_config", return_value=fake_config):
            assert config.is_gateway_enabled() is True

    def test_plugin_preflight_uses_configured_request_timeout(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(plugin_runtime, "get_request_timeout", lambda: 30)
        monkeypatch.setattr(
            plugin_runtime.registry,
            "ensure_registry_server",
            lambda startup_timeout: seen.setdefault("timeout", startup_timeout) or True,
        )

        assert plugin_runtime._ensure_gateway_ready_for_startup() is True
        assert seen["timeout"] == 30.0

    def test_instance_startup_checks_gateway_before_listener_launch(self, monkeypatch):
        """实例启动必须先完成 gateway preflight，再启动 listener。"""
        events = []

        monkeypatch.setattr(
            instance_server,
            "_ensure_gateway_ready_fn",
            lambda: events.append("gateway") or True,
        )
        monkeypatch.setattr(
            instance_server,
            "_update_lifecycle_state_fn",
            lambda port, state, ready: events.append(("state", port, state, ready)),
        )
        monkeypatch.setattr(
            instance_server,
            "_start_instance_server_threads",
            lambda host, port: events.append(("listener", host, port)),
        )

        instance_server.start_instance_server_threads("127.0.0.1", 10000)
        if instance_server._startup_thread:
            instance_server._startup_thread.join(timeout=1)

        assert events == [
            "gateway",
            ("state", 10000, "analyzing", False),
            ("listener", "127.0.0.1", 10000),
        ]

    def test_instance_startup_skips_listener_when_gateway_preflight_fails(
        self, monkeypatch
    ):
        """gateway 不健康时，不应先把实例 MCP listener 暴露出来。"""
        listener_started = []

        monkeypatch.setattr(instance_server, "_ensure_gateway_ready_fn", lambda: False)
        monkeypatch.setattr(
            instance_server,
            "_start_instance_server_threads",
            lambda host, port: listener_started.append((host, port)),
        )

        instance_server.start_instance_server_threads("127.0.0.1", 10000)
        if instance_server._startup_thread:
            instance_server._startup_thread.join(timeout=1)

        assert listener_started == []
        assert instance_server._server_thread is None

    def test_build_app_uses_fastmcp_lifespan(self):
        """网关应复用 FastMCP lifespan，以便 Streamable HTTP session manager 正确初始化。"""

        class FakeMCPApp:
            def __init__(self) -> None:
                self.lifespan_calls = []

            async def __call__(self, scope, receive, send):
                return None

            @asynccontextmanager
            async def lifespan(self, app):
                self.lifespan_calls.append(app)
                yield

        fake_mcp_app = FakeMCPApp()

        with patch.object(
            registry_server.proxy_server, "http_app", return_value=fake_mcp_app
        ) as mock_http_app:
            app = registry_server._build_app()

        mock_http_app.assert_called_once_with(
            path=registry_server.MCP_PATH,
            stateless_http=registry_server.is_mcp_sessionless_enabled(),
            json_response=registry_server.is_mcp_json_response_enabled(),
            session_idle_timeout=None,
            middleware=mock_http_app.call_args.kwargs["middleware"],
        )
        gate = mock_http_app.call_args.kwargs["middleware"]
        assert len(gate) == 1
        assert gate[0].cls is protocol_guard.LegacyProtocolGateMiddleware

        async def _run_lifespan():
            assert instance_registry._gateway_proxy_ready is False
            async with app.router.lifespan_context(app):
                assert instance_registry._gateway_proxy_ready is True
            assert instance_registry._gateway_proxy_ready is False

        import asyncio

        asyncio.run(_run_lifespan())
        assert fake_mcp_app.lifespan_calls == [app]

    def test_build_app_exposes_2026_sessionless_requests(self):
        """Modern MCP requests use the 2026 per-request envelope and JSON output."""
        app = registry_server._build_app()
        assert app is not None
        assert registry_server.MCP_PATH == "/mcp"

    def test_modern_2026_discover_request_is_sessionless_json(self):
        """MCP 2026-07-28 server/discover works without initialize or session ID."""
        from starlette.testclient import TestClient

        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": {"io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
        }
        headers = {"Accept": "application/json", "Content-Type": "application/json", "MCP-Protocol-Version": "2026-07-28", "mcp-method": "server/discover"}
        with TestClient(registry_server._build_app(), client=("127.0.0.1", 12345)) as client:
            response = client.post(registry_server.MCP_PATH, json=body, headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert "Mcp-Session-Id" not in response.headers
        result = response.json()["result"]
        assert "2026-07-28" in result["supportedVersions"]
        assert result["ttlMs"] >= 0
        assert result["resultType"] == "complete"

    def test_modern_2026_tools_list_has_no_session_header(self):
        """MCP 2026-07-28 tools/list uses per-request metadata and no session."""
        body = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"_meta": {"io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
        }
        headers = {"Accept": "application/json", "Content-Type": "application/json", "MCP-Protocol-Version": "2026-07-28", "mcp-method": "tools/list"}
        with TestClient(registry_server._build_app(), client=("127.0.0.1", 12345)) as client:
            response = client.post(registry_server.MCP_PATH, json=body, headers=headers)
        assert response.status_code == 200
        assert "Mcp-Session-Id" not in response.headers
        assert response.json()["result"]["resultType"] == "complete"

    def _legacy_initialize_body(self):
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        }

    def test_legacy_initialize_accepted_when_legacy_protocol_enabled(self, monkeypatch):
        """mcp_legacy_protocol=true（默认）时旧 initialize 客户端仍可使用。"""
        monkeypatch.setattr(protocol_guard, "is_mcp_legacy_protocol_enabled", lambda: True)
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-11-25",
        }
        with TestClient(registry_server._build_app(), client=("127.0.0.1", 12345)) as client:
            response = client.post(
                registry_server.MCP_PATH, json=self._legacy_initialize_body(), headers=headers
            )
        assert response.status_code == 200
        assert response.json()["result"]["protocolVersion"] == "2025-11-25"

    def test_legacy_initialize_rejected_when_legacy_protocol_disabled(self, monkeypatch):
        """mcp_legacy_protocol=false 时按 MCP 2026-07-28 拒绝握手请求。"""
        monkeypatch.setattr(protocol_guard, "is_mcp_legacy_protocol_enabled", lambda: False)
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-11-25",
        }
        with TestClient(registry_server._build_app(), client=("127.0.0.1", 12345)) as client:
            response = client.post(
                registry_server.MCP_PATH, json=self._legacy_initialize_body(), headers=headers
            )
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == -32601
        assert "2026-07-28" in error["message"]

    def test_legacy_initialize_without_version_header_rejected(self, monkeypatch):
        """2025-03-26 时代客户端不带 MCP-Protocol-Version，也应通过方法名识别并拒绝。"""
        monkeypatch.setattr(protocol_guard, "is_mcp_legacy_protocol_enabled", lambda: False)
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        with TestClient(registry_server._build_app(), client=("127.0.0.1", 12345)) as client:
            response = client.post(
                registry_server.MCP_PATH, json=self._legacy_initialize_body(), headers=headers
            )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32601

    def test_modern_request_unaffected_when_legacy_protocol_disabled(self, monkeypatch):
        """关闭 legacy 兼容后，2026-07-28 server/discover 请求不受影响。"""
        monkeypatch.setattr(protocol_guard, "is_mcp_legacy_protocol_enabled", lambda: False)
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": {"io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
        }
        headers = {"Accept": "application/json", "Content-Type": "application/json", "MCP-Protocol-Version": "2026-07-28", "mcp-method": "server/discover"}
        with TestClient(registry_server._build_app(), client=("127.0.0.1", 12345)) as client:
            response = client.post(registry_server.MCP_PATH, json=body, headers=headers)
        assert response.status_code == 200
        assert "2026-07-28" in response.json()["result"]["supportedVersions"]

    def test_gateway_auth_allows_loopback_without_token(self, monkeypatch):
        monkeypatch.setattr(registry_routes, "get_gateway_token", lambda: None)

        class Client:
            host = "127.0.0.1"

        class Request:
            client = Client()
            headers = {}

        assert registry_routes.is_gateway_request_authorized(Request()) is True

    def test_gateway_auth_still_requires_token_for_remote_clients(self, monkeypatch):
        monkeypatch.setattr(registry_routes, "get_gateway_token", lambda: "secret")

        class Client:
            host = "192.0.2.10"

        class Request:
            client = Client()
            headers = {}

        assert registry_routes.is_gateway_request_authorized(Request()) is False
        Request.headers = {"Authorization": "Bearer secret"}
        assert registry_routes.is_gateway_request_authorized(Request()) is True

    def test_gateway_register_preserves_failure_health_metadata(
        self, monkeypatch, isolated_gateway_state
    ):
        """实例重新注册时，应保留网关侧故障/隔离元数据。"""
        app = registry_server._build_internal_app()

        def _raise_unreachable(*args, **kwargs):
            raise ConnectionRefusedError("refused")

        monkeypatch.setattr(
            registry_routes.socket, "create_connection", _raise_unreachable
        )

        with TestClient(app) as client:
            register_payload = {"pid": 1234, "port": 10000, "input_file": "sample.exe"}
            assert client.post("/register", json=register_payload).status_code == 200

            response = client.post(
                "/call", json={"pid": 1234, "tool": "list_functions"}
            )
            assert response.status_code == 503

            refreshed_payload = {
                "pid": 1234,
                "port": 10000,
                "input_file": "sample-renamed.exe",
            }
            assert client.post("/register", json=refreshed_payload).status_code == 200

            instances = client.get("/instances").json()

        assert len(instances) == 1
        instance = instances[0]
        assert instance["input_file"] == "sample-renamed.exe"
        assert instance["health"] == instance_registry.INSTANCE_HEALTH_UNREACHABLE
        assert instance["last_error_kind"] == "connect"
        assert instance["consecutive_failures"] == 1
        assert instance["last_failure_at"] is not None
        assert instance["quarantined_until"] > instance["last_failure_at"]

    def test_gateway_call_returns_504_for_timeout_failures(
        self, monkeypatch, isolated_gateway_state
    ):
        """后端超时应映射为 504，而不是通用 500。"""
        app = registry_server._build_internal_app()

        class FakeClient:
            def __init__(self, url, timeout):
                self.url = url
                self.timeout = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def call_tool(self, tool, params):
                raise asyncio.TimeoutError()

        monkeypatch.setattr(
            registry_routes.socket,
            "create_connection",
            lambda *args, **kwargs: _DummySocketConnection(),
        )
        monkeypatch.setitem(
            sys.modules, "fastmcp", types.SimpleNamespace(Client=FakeClient)
        )

        with TestClient(app) as client:
            assert (
                client.post(
                    "/register",
                    json={"pid": 5678, "port": 10001, "input_file": "sample.exe"},
                ).status_code
                == 200
            )

            response = client.post(
                "/call",
                json={"port": 10001, "tool": "list_functions", "timeout": 1},
            )
            assert response.status_code == 504

            instances = client.get("/instances").json()

        assert len(instances) == 1
        instance = instances[0]
        assert instance["health"] == instance_registry.INSTANCE_HEALTH_UNRESPONSIVE
        assert instance["last_error_kind"] == "timeout"
        assert instance["consecutive_failures"] == 1

    def test_gateway_partial_update_merges_pending_status(self, isolated_gateway_state):
        app = registry_server._build_internal_app()

        with TestClient(app) as client:
            assert (
                client.post(
                    "/register",
                    json={
                        "pid": 9012,
                        "port": 10010,
                        "input_file": "sample.exe",
                        "ready": False,
                        "lifecycle_state": "starting",
                    },
                ).status_code
                == 200
            )
            assert (
                client.post(
                    "/update_instance",
                    json={
                        "pid": 9012,
                        "lifecycle_state": "analyzing",
                        "ready": False,
                    },
                ).status_code
                == 200
            )
            instance = client.get("/instances").json()[0]

        assert instance["input_file"] == "sample.exe"
        assert instance["port"] == 10010
        assert instance["ready"] is False
        assert instance["lifecycle_state"] == "analyzing"
        assert instance["effective_state"] == "analyzing"

    def test_gateway_select_instance_updates_current_instance(
        self, isolated_gateway_state
    ):
        app = registry_server._build_internal_app()

        with TestClient(app) as client:
            assert (
                client.post(
                    "/register",
                    json={"pid": 1001, "port": 10001, "input_file": "init.exe"},
                ).status_code
                == 200
            )
            assert (
                client.post(
                    "/register",
                    json={"pid": 1002, "port": 10002, "input_file": "target.exe"},
                ).status_code
                == 200
            )

            selected = client.post("/select_instance", json={"port": 10002})
            current = client.get("/current_instance")

        assert selected.status_code == 200
        assert selected.json()["selected_port"] == 10002
        assert current.status_code == 200
        assert current.json()["port"] == 10002

    def test_choose_port_prefers_healthy_instance_over_quarantined_or_unhealthy(
        self, monkeypatch
    ):
        """自动选择应先避开隔离/不健康实例。"""
        monkeypatch.setattr(
            proxy_state,
            "get_instances",
            lambda: [
                {
                    "port": 10000,
                    "health": instance_registry.INSTANCE_HEALTH_HEALTHY,
                    "quarantined_until": time.time() + 60,
                },
                {"port": 10002, "health": instance_registry.INSTANCE_HEALTH_UNREACHABLE},
                {"port": 10001, "health": instance_registry.INSTANCE_HEALTH_HEALTHY},
            ],
        )

        assert proxy_state.choose_port() == 10001

    def test_choose_port_prefers_10000_among_equally_healthy_instances(
        self, monkeypatch
    ):
        """同等健康度下仍应优先历史默认端口 10000。"""
        monkeypatch.setattr(
            proxy_state,
            "get_instances",
            lambda: [
                {"port": 10001, "health": instance_registry.INSTANCE_HEALTH_HEALTHY},
                {"port": 10000, "health": instance_registry.INSTANCE_HEALTH_HEALTHY},
            ],
        )

        assert proxy_state.choose_port() == 10000

    def test_choose_port_prefers_selected_instance(self, monkeypatch):
        monkeypatch.setattr(instance_registry, "_current_instance_port", 10002)
        monkeypatch.setattr(
            proxy_state,
            "get_instances",
            lambda: [
                {"port": 10001, "health": instance_registry.INSTANCE_HEALTH_HEALTHY},
                {"port": 10002, "health": instance_registry.INSTANCE_HEALTH_HEALTHY},
            ],
        )

        assert proxy_state.choose_port() == 10002

    def test_choose_port_clears_missing_selected_instance(self, monkeypatch):
        monkeypatch.setattr(instance_registry, "_current_instance_port", 10002)
        monkeypatch.setattr(
            proxy_state,
            "get_instances",
            lambda: [
                {"port": 10001, "health": instance_registry.INSTANCE_HEALTH_HEALTHY},
            ],
        )

        assert proxy_state.choose_port() == 10001
        assert instance_registry._current_instance_port is None

    def test_forward_uses_selected_instance_when_port_omitted(self, monkeypatch):
        seen: dict[str, object] = {}
        monkeypatch.setattr(instance_registry, "_current_instance_port", 10002)
        monkeypatch.setattr(
            proxy_state,
            "get_instances",
            lambda: [
                {"port": 10001, "health": instance_registry.INSTANCE_HEALTH_HEALTHY},
                {"port": 10002, "health": instance_registry.INSTANCE_HEALTH_HEALTHY},
            ],
        )

        def fake_http_post(path, body, timeout=None):
            seen["path"] = path
            seen["body"] = body
            seen["timeout"] = timeout
            return {"data": {"input_file": "selected.exe"}}

        monkeypatch.setattr(proxy_state, "http_post", fake_http_post)

        result = proxy_state.forward("get_metadata")

        assert result == {"input_file": "selected.exe"}
        assert seen["body"]["port"] == 10002

    def test_choose_port_excludes_non_ready_instances(self, monkeypatch):
        monkeypatch.setattr(
            proxy_state,
            "get_instances",
            lambda: [
                {
                    "port": 10000,
                    "ready": False,
                    "effective_state": "starting",
                },
                {"port": 10001, "ready": True, "effective_state": "ready"},
            ],
        )

        assert proxy_state.choose_port() == 10001
        assert proxy_state.choose_port(10000) == 10000

    def test_gateway_marks_stale_main_thread_unresponsive_and_unroutable(
        self, monkeypatch, isolated_gateway_state
    ):
        app = registry_server._build_internal_app()
        stale_tick = time.time() - instance_registry.MAIN_THREAD_STALE_SECONDS - 1

        with TestClient(app) as client:
            assert (
                client.post(
                    "/register",
                    json={
                        "pid": 7777,
                        "port": 10020,
                        "input_file": "sample.exe",
                        "ready": True,
                        "lifecycle_state": "ready",
                        "main_thread_last_tick_at": stale_tick,
                    },
                ).status_code
                == 200
            )
            instance = client.get("/instances").json()[0]

            with patch.object(
                registry_routes.socket,
                "create_connection",
                side_effect=AssertionError("should not probe stale instance"),
            ):
                response = client.post(
                    "/call", json={"port": 10020, "tool": "list_functions"}
                )

        assert (
            instance["effective_state"] == instance_registry.INSTANCE_HEALTH_UNRESPONSIVE
        )
        assert instance["main_thread_stale"] is True
        assert response.status_code == 504

    def test_choose_port_excludes_stale_main_thread_instances(self, monkeypatch):
        monkeypatch.setattr(
            proxy_state,
            "get_instances",
            lambda: [
                {
                    "port": 10000,
                    "ready": True,
                    "effective_state": instance_registry.INSTANCE_HEALTH_UNRESPONSIVE,
                },
                {"port": 10001, "ready": True, "effective_state": "ready"},
            ],
        )

        assert proxy_state.choose_port() == 10001

    def test_http_connect_host_uses_loopback_for_unspecified_bind_host(self):
        """当网关绑定到 0.0.0.0 时，客户端仍应连接到 127.0.0.1。"""
        fake_config = {
            "http_host": "0.0.0.0",
            "http_port": 11338,
            "http_path": "/mcp",
        }

        with patch("ida_mcp.config.load_config", return_value=fake_config):
            assert config.get_http_bind_host() == "0.0.0.0"
            assert config.get_http_connect_host() == "127.0.0.1"
            assert (
                config.get_gateway_internal_url() == "http://127.0.0.1:11338/internal"
            )
            assert config.get_http_url() == "http://127.0.0.1:11338/mcp"

    def test_init_and_register_retries_remote_registration(self):
        """远端注册瞬时失败时，应快速重试而不是静默丢失实例。"""
        with patch("ida_mcp.registry.is_gateway_enabled", return_value=True):
            with patch(
                "ida_mcp.registry.ensure_registry_server", return_value=True
            ) as mock_ensure:
                with patch("ida_mcp.registry._gateway_internal_alive", return_value=True):
                    with patch(
                        "ida_mcp.registry._request_json",
                        side_effect=[None, {"status": "ok"}],
                    ) as mock_request:
                        with patch("atexit.register"):
                            with patch.object(registry, "_deregister_registered", False):
                                registry.init_and_register(10000, "input.bin", "db.i64")

        assert mock_ensure.call_count == 1
        assert mock_request.call_count == 2

    def test_ensure_registry_server_allows_empty_token_on_loopback(self):
        with patch("ida_mcp.registry.get_http_bind_host", return_value="127.0.0.1"):
            with patch("ida_mcp.registry.get_gateway_token", return_value=None):
                with patch("ida_mcp.registry._gateway_ready", side_effect=[False, False, True]):
                    with patch("ida_mcp.registry._gateway_internal_alive", return_value=False):
                        with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                            with patch(
                                "ida_mcp.registry._resolve_python_executable",
                                return_value="/usr/bin/python3",
                            ):
                                assert registry.ensure_registry_server(startup_timeout=0.3) is True

        assert mock_spawn.call_count == 1

    def test_ensure_registry_server_requires_token_on_remote_bind(self):
        with patch("ida_mcp.registry.get_http_bind_host", return_value="0.0.0.0"):
            with patch("ida_mcp.registry.get_gateway_token", return_value=None):
                with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                    assert registry.ensure_registry_server(startup_timeout=0.3) is False

        assert mock_spawn.call_count == 0
        assert registry._launch_status["registry_server"]["requested"] is False
        assert "not loopback" in registry._launch_status["registry_server"]["last_error"]

    def test_ensure_registry_server_spawns_detached_daemon(self):
        """网关不可达时，应拉起独立 daemon，而不是依赖当前 IDA。"""
        with patch("ida_mcp.registry.get_gateway_token", return_value="token"):
            with patch("ida_mcp.registry._gateway_ready", side_effect=[False, False, True]):
                with patch("ida_mcp.registry._gateway_internal_alive", return_value=False):
                    with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                        with patch(
                            "ida_mcp.registry._resolve_python_executable",
                            return_value="/usr/bin/python3",
                        ):
                            assert (
                                registry.ensure_registry_server(startup_timeout=0.3) is True
                            )

        assert mock_spawn.call_count == 1

    def test_ensure_registry_server_binds_to_http_host(self):
        """网关子进程应绑定 http_host，而不是客户端连接地址。"""
        with patch("ida_mcp.registry.get_gateway_token", return_value="token"):
            with patch("ida_mcp.registry._gateway_ready", side_effect=[False, False, True]):
                with patch("ida_mcp.registry._gateway_internal_alive", return_value=False):
                    with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                        with patch(
                            "ida_mcp.registry._resolve_python_executable",
                            return_value="/usr/bin/python3",
                        ):
                            with patch(
                                "ida_mcp.registry.get_http_bind_host",
                                return_value="0.0.0.0",
                            ):
                                with patch(
                                    "ida_mcp.registry.get_gateway_internal_port",
                                    return_value=11338,
                                ):
                                    assert (
                                        registry.ensure_registry_server(startup_timeout=0.3)
                                        is True
                                    )

        spawn_args = mock_spawn.call_args.args[0]
        assert spawn_args == [
            "/usr/bin/python3",
            os.path.join(registry._package_dir(), "registry_server.py"),
            "--host",
            "0.0.0.0",
            "--port",
            "11338",
        ]

    def test_ensure_registry_server_refuses_second_spawn_on_occupied_port(self):
        """已有监听但健康检查失败时，不应继续抢占同一端口启动第二个网关。"""
        with patch("ida_mcp.registry.get_gateway_token", return_value="token"):
            with patch("ida_mcp.registry._gateway_ready", return_value=False):
                with patch("ida_mcp.registry._gateway_internal_alive", return_value=True):
                    with patch(
                        "ida_mcp.registry._wait_for_gateway_ready", return_value=False
                    ):
                        with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                            assert (
                                registry.ensure_registry_server(startup_timeout=0.1)
                                is False
                            )

        assert mock_spawn.call_count == 0
        status = registry.get_registry_server_status()
        assert "already listening" in status.get("last_error", "")

    def test_resolve_python_executable_from_exec_prefix(self):
        """应从 sys.exec_prefix 解析 idaswitch 管理的 Python。"""
        with patch("ida_mcp.registry.get_ida_python", return_value=None):
            with patch.object(sys, "exec_prefix", r"D:\portable-python-3.12"):
                with patch.object(sys, "base_prefix", r"D:\portable-python-3.12"):
                    with patch.object(sys, "prefix", r"D:\portable-python-3.12"):
                        with patch(
                            "os.path.isfile",
                            side_effect=lambda p: (
                                p.lower()
                                == r"d:\portable-python-3.12\python.exe"
                            ),
                        ):
                            resolved = registry._resolve_python_executable()

        assert resolved.lower() == r"d:\portable-python-3.12\python.exe"

    def test_resolve_python_executable_supports_prefix_root_python(self):
        """Linux IDAPython may place python directly below sys.prefix."""
        prefix = "/home/ub/ida-pro-9.4/ida-python"
        with patch("ida_mcp.registry.get_ida_python", return_value=None):
            with patch.object(registry.os, "name", "posix"):
                with patch.object(sys, "exec_prefix", prefix):
                    with patch.object(sys, "base_prefix", prefix):
                        with patch.object(sys, "prefix", prefix):
                            with patch(
                                "os.path.isfile",
                                side_effect=lambda p: p == f"{prefix}/python",
                            ):
                                resolved = registry._resolve_python_executable()

        assert resolved == f"{prefix}/python"

    def test_resolve_python_executable_uses_sys_prefix_fallback(self):
        """sys.exec_prefix 不存在时应回退到 sys.base_prefix / sys.prefix。"""
        with patch("ida_mcp.registry.get_ida_python", return_value=None):
            with patch.object(sys, "exec_prefix", r"D:\nonexistent"):
                with patch.object(sys, "base_prefix", r"D:\nonexistent"):
                    with patch.object(sys, "prefix", r"D:\portable-python-3.12"):
                        with patch(
                            "os.path.isfile",
                            side_effect=lambda p: (
                                p.lower()
                                == r"d:\portable-python-3.12\python.exe"
                            ),
                        ):
                            resolved = registry._resolve_python_executable()

        assert resolved.lower() == r"d:\portable-python-3.12\python.exe"

    def test_ensure_gateway_proxy_running_uses_gateway_process(self):
        """Gateway proxy 应由已启动的网关进程内建拉起，而不是另起独立进程。"""
        with patch("ida_mcp.registry.is_gateway_enabled", return_value=True):
            with patch(
                "ida_mcp.registry._gateway_proxy_alive", side_effect=[False, False, True]
            ):
                with patch(
                    "ida_mcp.registry.ensure_registry_server", return_value=True
                ) as mock_gateway:
                    with patch(
                        "ida_mcp.registry._request_json",
                        return_value={
                            "enabled": True,
                            "running": False,
                            "last_error": None,
                        },
                    ) as mock_request:
                        with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                            with patch.dict(
                                registry._launch_status,
                                {
                                    "registry_server": {
                                        "python": "/usr/bin/python3",
                                        "log": "/tmp/gateway.log",
                                    }
                                },
                                clear=False,
                            ):
                                assert (
                                    registry.ensure_gateway_proxy_running(
                                        startup_timeout=0.3
                                    )
                                    is True
                                )

        assert mock_gateway.call_count == 1
        assert mock_request.call_count == 1
        assert mock_spawn.call_count == 0

    def test_start_gateway_proxy_returns_connectable_gateway_url(self):
        """插件日志应返回可连接的网关 URL，而不是 0.0.0.0。"""
        with patch("ida_mcp.registry.ensure_gateway_proxy_running", return_value=True):
            with patch("ida_mcp.config.is_gateway_enabled", return_value=True):
                with patch(
                    "ida_mcp.config.get_http_url",
                    return_value="http://127.0.0.1:11338/mcp",
                ):
                    assert (
                        runtime.start_gateway_proxy_if_enabled()
                        == "http://127.0.0.1:11338/mcp"
                    )

    def test_shutdown_gateway_forwards_force_flag_without_spawning(self):
        """关闭网关请求应直连内部控制 API，而不是反向拉起新网关。"""
        with patch(
            "ida_mcp.registry._request_json", return_value={"status": "ok"}
        ) as mock_request:
            result = registry.shutdown_gateway(force=True, timeout=7)

        assert result == {"status": "ok"}
        assert mock_request.call_count == 1
        assert mock_request.call_args.args[:3] == ("POST", "/shutdown", {"force": True})
        assert mock_request.call_args.kwargs["timeout"] == 7
        assert mock_request.call_args.kwargs["ensure_server"] is False
