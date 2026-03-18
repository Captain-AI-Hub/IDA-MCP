"""测试生命周期管理工具 (open_in_ida, close_ida)。

注意：这些测试涉及启动和关闭进程，可能会影响正在运行的 IDA 实例。
建议在受控环境中运行。
"""
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

# 添加项目根目录到 sys.path 以便导入 ida_mcp 模块
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ida_mcp import config
from ida_mcp import registry
from ida_mcp import registry_server
from ida_mcp.proxy import lifecycle
from ida_mcp import runtime

pytestmark = pytest.mark.lifecycle


def _load_plugin_module(monkeypatch):
    """Load the top-level ida_mcp.py plugin with fake IDA modules for unit testing."""
    module_name = f"ida_mcp_plugin_test_{time.time_ns()}"
    plugin_path = os.path.join(PROJECT_ROOT, "ida_mcp.py")
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

    def test_open_in_ida_launch(self, tool_caller):
        """Test launching IDA."""
        # Use project sample file
        sample_path = os.path.join(PROJECT_ROOT, "test", "samples", "complex.exe")
        
        # Ensure file exists
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

        # Wait for IDA to be ready
        print("\nWaiting for IDA to initialize...")
        max_retries = 30
        for i in range(max_retries):
            try:
                # Try to list instances to see if our instance registered
                instances = tool_caller("list_instances", {})
                if isinstance(instances, list) and len(instances) > 0:
                    print(f"IDA instance found after {i+1} retries.")
                    # Wait a bit more for full initialization
                    time.sleep(5)
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
             print("Warning: IDA instance did not register in time. Subsequent tests might fail.")


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
        assert "not found" in result["error"] or "not configured" in result["error"] or "Failed to launch" in result["error"]

    def test_open_in_ida_reserves_incrementing_ports(self):
        """连续启动未注册实例时，端口预留应继续向上分配。"""
        launch_root = os.path.join(tempfile.gettempdir(), "ida-launch-root")
        bundle_dir = os.path.join(launch_root, "ida_mcp_open_20260317-120000-000001")
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch("ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable):
                with patch("ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000):
                    with patch("ida_mcp.proxy.lifecycle.get_instances", return_value=[]):
                        with patch("ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir", return_value=launch_root):
                            with patch("ida_mcp.proxy.lifecycle._is_port_bindable", return_value=True):
                                with patch("ida_mcp.proxy.lifecycle._launch_bundle_dir", return_value=bundle_dir):
                                    with patch("ida_mcp.proxy.lifecycle._stage_target_file_for_launch", return_value=(__file__, __file__)):
                                        with patch("subprocess.Popen") as mock_popen:
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
            with patch("ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable):
                with patch("ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000):
                    with patch("ida_mcp.proxy.lifecycle.get_instances", return_value=[]):
                        with patch("ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir", return_value=launch_root):
                            with patch("ida_mcp.proxy.lifecycle._is_port_bindable", return_value=True):
                                with patch("ida_mcp.proxy.lifecycle._launch_bundle_dir", return_value=bundle_dir):
                                    with patch("ida_mcp.proxy.lifecycle._stage_target_file_for_launch", return_value=(__file__, __file__)):
                                        with patch("subprocess.Popen") as mock_popen:
                                            result = lifecycle.open_in_ida(__file__, extra_args=["-A", "-Llog.txt"])

        assert result["status"] == "ok"
        cmd = mock_popen.call_args.args[0]
        assert "-A" in cmd
        assert "-Llog.txt" in cmd
        assert mock_popen.call_args.kwargs["env"]["IDA_MCP_AUTO_START"] == "1"

    def test_resolve_launch_inputs_prefers_existing_database(self, tmp_path):
        sample = tmp_path / "sample.exe"
        database = tmp_path / "sample.exe.i64"
        sample.write_bytes(b"test")
        database.write_bytes(b"idb")

        launch_target, input_file_path, database_path = lifecycle._resolve_launch_inputs(str(sample))

        assert launch_target == str(database.resolve())
        assert input_file_path == str(sample.resolve())
        assert database_path == str(database.resolve())

    def test_get_open_in_ida_bundle_dir_prefers_env_over_config(self):
        with patch.dict(os.environ, {"IDA_MCP_BUNDLE_DIR": r"D:\env-temp"}, clear=False):
            with patch("ida_mcp.config.load_config", return_value={"open_in_ida_bundle_dir": r"E:\config-temp"}):
                assert config.get_open_in_ida_bundle_dir() == r"D:\env-temp"

    def test_launch_bundle_dir_uses_timestamp_directory(self, tmp_path):
        root_dir = str(tmp_path)
        with patch("ida_mcp.proxy.lifecycle._timestamp_dir_name", return_value="ida_mcp_open_20260317-120000-000001"):
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
            with patch("ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable):
                with patch("ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000):
                    with patch("ida_mcp.proxy.lifecycle.get_instances", return_value=[]):
                        with patch("ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir", return_value=bundle_root):
                            with patch("ida_mcp.proxy.lifecycle._is_port_bindable", return_value=True):
                                with patch("ida_mcp.proxy.lifecycle._launch_bundle_dir", return_value=bundle_dir) as mock_launch_bundle:
                                    with patch("ida_mcp.proxy.lifecycle._stage_target_file_for_launch", return_value=(staged_file, staged_file)) as mock_stage:
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
            with patch("ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable):
                with patch("ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000):
                    with patch("ida_mcp.proxy.lifecycle.get_instances", return_value=[]):
                        with patch("ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir", return_value=None):
                            with patch("ida_mcp.proxy.lifecycle._is_port_bindable", return_value=True):
                                with patch("ida_mcp.proxy.lifecycle._use_direct_target_file", return_value=(direct_target, None)) as mock_direct:
                                    with patch("subprocess.Popen") as mock_popen:
                                        result = lifecycle.open_in_ida(__file__)

        mock_direct.assert_called_once_with(__file__)
        assert result["launch_bundle"] is None
        assert result["staged_file"] is None
        assert result["launch_target"] == direct_target
        assert direct_target in mock_popen.call_args.args[0]

    def test_stage_target_file_for_launch_preserves_basename_when_staging(self, tmp_path):
        copied = []
        bundle_dir = str(tmp_path / "launch-bundle")
        expected_local = os.path.join(bundle_dir, "same.bin")

        with patch("ida_mcp.proxy.lifecycle.shutil.copy2", side_effect=lambda src, dst: copied.append((src, dst))):
            staged_path, staged_local = lifecycle._stage_target_file_for_launch("/home/user/same.bin", bundle_dir)

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

        launch_path, staged_requested = lifecycle._stage_target_file_for_launch(str(sample), str(bundle_dir))

        assert launch_path == str((bundle_dir / database.name).resolve())
        assert staged_requested == str((bundle_dir / sample.name).resolve())
        assert (bundle_dir / sample.name).exists()
        assert (bundle_dir / database.name).exists()

    def test_open_in_ida_releases_reserved_port_when_launch_fails(self):
        """启动失败后，应释放预留端口以便后续重试。"""
        with patch.dict(lifecycle._RESERVED_LAUNCH_PORTS, {}, clear=True):
            with patch("ida_mcp.proxy.lifecycle.get_ida_path", return_value=sys.executable):
                with patch("ida_mcp.proxy.lifecycle.get_ida_default_port", return_value=10000):
                    with patch("ida_mcp.proxy.lifecycle.get_instances", return_value=[]):
                        with patch("ida_mcp.proxy.lifecycle.get_open_in_ida_bundle_dir", return_value=None):
                            with patch("ida_mcp.proxy.lifecycle._is_port_bindable", return_value=True):
                                with patch("ida_mcp.proxy.lifecycle._use_direct_target_file", return_value=(__file__, None)):
                                    with patch("subprocess.Popen", side_effect=RuntimeError("boom")):
                                        result = lifecycle.open_in_ida(__file__)
            assert lifecycle._RESERVED_LAUNCH_PORTS == {}

        assert "error" in result


class TestLifecycleClose:
    """Lifecycle management tests - Close IDA.
    Runs last to clean up environment.
    """

    def test_close_ida(self, tool_caller):
        """Test closing IDA (runs last)."""
        # This will actually close IDA!
        print("\nAttempting to close IDA...")
        result = tool_caller("close_ida", {"save": False})
        
        if "error" in result:
             # If no instance is running, that's fine for this test context if we just want to clean up
             # But if we expected it to run, maybe we should warn
             print(f"Close IDA result: {result}")
        else:
             assert "status" in result
             assert result["status"] == "ok"
             
        # Wait a bit for process cleanup
        time.sleep(2)


class TestRegistryStartup:
    """网关启动与注册的回归测试。"""

    def test_instance_startup_checks_gateway_before_listener_launch(self, monkeypatch):
        """实例启动必须先完成 gateway preflight，再启动 listener。"""
        plugin = _load_plugin_module(monkeypatch)
        events = []

        monkeypatch.setattr(
            plugin,
            "_ensure_gateway_ready_for_startup",
            lambda: events.append("gateway") or True,
        )
        monkeypatch.setattr(
            plugin,
            "_start_instance_server_threads",
            lambda host, port: events.append(("listener", host, port)),
        )

        plugin.start_server_async("127.0.0.1", 10000)
        if plugin._startup_thread:
            plugin._startup_thread.join(timeout=1)

        assert events == ["gateway", ("listener", "127.0.0.1", 10000)]

    def test_instance_startup_skips_listener_when_gateway_preflight_fails(self, monkeypatch):
        """gateway 不健康时，不应先把实例 MCP listener 暴露出来。"""
        plugin = _load_plugin_module(monkeypatch)
        listener_started = []

        monkeypatch.setattr(plugin, "_ensure_gateway_ready_for_startup", lambda: False)
        monkeypatch.setattr(
            plugin,
            "_start_instance_server_threads",
            lambda host, port: listener_started.append((host, port)),
        )

        plugin.start_server_async("127.0.0.1", 10000)
        if plugin._startup_thread:
            plugin._startup_thread.join(timeout=1)

        assert listener_started == []
        assert plugin._server_thread is None

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

        with patch.object(registry_server.proxy_server, "http_app", return_value=fake_mcp_app):
            app = registry_server._build_app()

        async def _run_lifespan():
            assert registry_server._proxy_ready is False
            async with app.router.lifespan_context(app):
                assert registry_server._proxy_ready is True
            assert registry_server._proxy_ready is False

        import asyncio

        asyncio.run(_run_lifespan())
        assert fake_mcp_app.lifespan_calls == [app]

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
            assert config.get_coordinator_url() == "http://127.0.0.1:11338/internal"
            assert config.get_http_url() == "http://127.0.0.1:11338/mcp"

    def test_init_and_register_retries_remote_registration(self):
        """远端注册瞬时失败时，应快速重试而不是静默丢失实例。"""
        with patch("ida_mcp.config.is_stdio_enabled", return_value=True):
            with patch("ida_mcp.config.is_http_enabled", return_value=False):
                with patch("ida_mcp.registry.ensure_registry_server", return_value=True) as mock_ensure:
                    with patch("ida_mcp.registry._request_json", side_effect=[None, {"status": "ok"}]) as mock_request:
                        with patch("atexit.register"):
                            with patch.object(registry, "_deregister_registered", False):
                                registry.init_and_register(10000, "input.bin", "db.i64")

        assert mock_ensure.call_count == 1
        assert mock_request.call_count == 2

    def test_ensure_registry_server_spawns_detached_daemon(self):
        """网关不可达时，应拉起独立 daemon，而不是依赖当前 IDA。"""
        with patch("ida_mcp.registry._gateway_ready", side_effect=[False, False, True]):
            with patch("ida_mcp.registry._coordinator_alive", return_value=False):
                with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                    with patch("ida_mcp.registry._resolve_python_executable", return_value="/usr/bin/python3"):
                        assert registry.ensure_registry_server(startup_timeout=0.3) is True

        assert mock_spawn.call_count == 1

    def test_ensure_registry_server_binds_to_http_host(self):
        """网关子进程应绑定 http_host，而不是客户端连接地址。"""
        with patch("ida_mcp.registry._gateway_ready", side_effect=[False, False, True]):
            with patch("ida_mcp.registry._coordinator_alive", return_value=False):
                with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                    with patch("ida_mcp.registry._resolve_python_executable", return_value="/usr/bin/python3"):
                        with patch("ida_mcp.registry.get_http_bind_host", return_value="0.0.0.0"):
                            with patch("ida_mcp.registry.get_coordinator_port", return_value=11338):
                                assert registry.ensure_registry_server(startup_timeout=0.3) is True

        spawn_args = mock_spawn.call_args.args[0]
        assert spawn_args == [
            "/usr/bin/python3",
            "-m",
            "ida_mcp.registry_server",
            "--host",
            "0.0.0.0",
            "--port",
            "11338",
        ]

    def test_ensure_registry_server_refuses_second_spawn_on_occupied_port(self):
        """已有监听但健康检查失败时，不应继续抢占同一端口启动第二个网关。"""
        with patch("ida_mcp.registry._gateway_ready", return_value=False):
            with patch("ida_mcp.registry._coordinator_alive", return_value=True):
                with patch("ida_mcp.registry._wait_for_gateway_ready", return_value=False):
                    with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                        assert registry.ensure_registry_server(startup_timeout=0.1) is False

        assert mock_spawn.call_count == 0
        status = registry.get_registry_server_status()
        assert "already listening" in status.get("last_error", "")

    def test_resolve_python_executable_prefers_ida_side_python(self):
        """当 sys.executable 指向 ida64.exe 时，应改用同目录的 python.exe。"""
        with patch.object(sys, "executable", r"D:\safetools\IDAPro-9.3\ida64.exe"):
            with patch.object(sys, "_base_executable", r"D:\safetools\IDAPro-9.3\ida64.exe", create=True):
                with patch("os.path.isfile", side_effect=lambda p: p.lower() == r"d:\safetools\idapro-9.3\python.exe"):
                    resolved = registry._resolve_python_executable()

        assert resolved.lower() == r"d:\safetools\idapro-9.3\python.exe"

    def test_ensure_http_proxy_running_uses_gateway_process(self):
        """HTTP proxy 应由已启动的网关进程内建拉起，而不是另起独立进程。"""
        with patch("ida_mcp.config.is_http_enabled", return_value=True):
            with patch("ida_mcp.registry._http_proxy_alive", side_effect=[False, False, True]):
                with patch("ida_mcp.registry.ensure_registry_server", return_value=True) as mock_gateway:
                    with patch("ida_mcp.registry._request_json", return_value={"enabled": True, "running": False, "last_error": None}) as mock_request:
                        with patch("ida_mcp.registry._spawn_detached") as mock_spawn:
                            with patch.dict(registry._launch_status, {"registry_server": {"python": "/usr/bin/python3", "log": "/tmp/gateway.log"}}, clear=False):
                                assert registry.ensure_http_proxy_running(startup_timeout=0.3) is True

        assert mock_gateway.call_count == 1
        assert mock_request.call_count == 1
        assert mock_spawn.call_count == 0

    def test_start_http_proxy_returns_connectable_gateway_url(self):
        """插件日志应返回可连接的网关 URL，而不是 0.0.0.0。"""
        with patch("ida_mcp.registry.ensure_http_proxy_running", return_value=True):
            with patch("ida_mcp.config.is_http_enabled", return_value=True):
                with patch("ida_mcp.config.get_http_url", return_value="http://127.0.0.1:11338/mcp"):
                    assert runtime.start_http_proxy_if_coordinator() == "http://127.0.0.1:11338/mcp"

    def test_shutdown_gateway_forwards_force_flag_without_spawning(self):
        """关闭网关请求应直连内部控制 API，而不是反向拉起新网关。"""
        with patch("ida_mcp.registry._request_json", return_value={"status": "ok"}) as mock_request:
            result = registry.shutdown_gateway(force=True, timeout=7)

        assert result == {"status": "ok"}
        assert mock_request.call_count == 1
        assert mock_request.call_args.args[:3] == ("POST", "/shutdown", {"force": True})
        assert mock_request.call_args.kwargs["timeout"] == 7
        assert mock_request.call_args.kwargs["ensure_server"] is False
