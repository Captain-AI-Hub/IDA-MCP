"""IDA Pro MCP 插件 (HTTP + 多实例网关注册)

功能综述
====================
本插件为每个启动的 IDA 实例提供一个最小化 **FastMCP HTTP** 服务, 暴露逆向分析能力给支持 MCP 的外部客户端。

核心特性:
    1. 启动/关闭采用"切换式"触发(再次运行插件即关闭)。
    2. 自动选择空闲端口 (从 10000 开始向上扫描), MCP 路径固定为 ``/mcp``。
    3. 插件会确保独立单端口网关已启动, 默认通过 ``127.0.0.1:11338/internal`` 完成注册与转发。
    4. 后续实例向网关注册, 仅在内存维护实例列表, 不落盘 (避免文件锁 / 清理问题)。
    5. 工具最小化: 仅保留 ``list_functions`` 与 ``instances`` (实例列表)。
    6. 可配合独立进程型代理 ``ida_mcp_proxy.py`` 统一访问多个实例。

运行时架构
--------------------
``IDA 实例 (N 个)`` → 各自运行 uvicorn FastMCP (HTTP) → 向网关登记元信息(pid, port, input_file 等)。
``网关`` 负责: 记录活跃实例; 暴露统一 MCP 入口; 将 /call 请求转发至目标实例。

线程与生命周期
--------------------
* uvicorn 服务器在 **后台守护线程** 中运行, 便于主线程继续响应 IDA 事件。
* 关闭流程: 设置 ``_uv_server.should_exit = True`` → 等待线程退出 → 调用网关注销。
* IDA 退出或插件终止时, 若仍在运行则自动停止并反注册。

端口选择策略
--------------------
* 若由 launcher 注入 bootstrap 环境变量 ``IDA_MCP_PORT`` 且合法, 则将其作为优先起点; 若已占用则继续向上扫描。
* 否则从 ``config.conf`` 中的 ``ida_default_port`` 起向上扫描 (最大 50 次)。
* 允许多个 IDA 实例并行, 避免端口冲突。

bootstrap 环境变量 (launcher 内部使用)
--------------------
* ``IDA_MCP_PORT``: 本次启动的优先端口起点。
* ``IDA_MCP_AUTO_START``: 请求插件在当前进程启动后立即拉起实例服务。

主要内部变量
--------------------
* ``_server_thread``: 后台 uvicorn 线程对象。
* ``_uv_server``: uvicorn Server 实例 (用于发出停止信号)。
* ``_active_port``: 当前实例实际使用端口。
* ``_stop_lock``: 防止并发关闭竞争。

公共函数概览
--------------------
* ``start_server_async(host, port)``: 启动 MCP 服务器 (线程)。
* ``stop_server()``: 发送退出信号并等待线程结束, 向网关注销。
* ``is_running()``: 判断当前服务器线程是否存活。

扩展建议
--------------------
未来可在 ``ida_mcp/server.py`` 内增量添加更多工具 (反编译、交叉引用、数据段搜索等)。网关 ``registry.py`` 已支持 /call 转发, 添加工具仅需在每个实例服务端注册, 代理端(可选)补一层转发包装。

使用方式
--------------------
1. 将本文件与 ``ida_mcp`` 目录复制到 IDA ``plugins/``。
2. 打开目标二进制, 分析完成后在菜单或快捷键中执行插件 (第一次执行 = 启动)。
3. 再次执行插件 = 停止并反注册。
4. 可启动多个 IDA 实例重复步骤 2, 通过网关统一访问。

调试提示
--------------------
* 如果端口被占用, 会自动向上扫描; 如全部失败, 仍可能抛出绑定异常 (检查是否被防火墙或安全软件占用)。
* 服务器崩溃日志会打印堆栈; 若需更详细日志可将 uvicorn log_level 改为 info/debug。

本文件只包含逻辑入口与生命周期管理, 实际工具定义在 ``ida_mcp/server.py``。
"""

import warnings

# 必须在任何可能导入 websockets 的模块之前设置过滤器
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"websockets\..*")
warnings.filterwarnings(
    "ignore", category=DeprecationWarning, message=r".*websockets.*"
)

import threading
import os
import site as _site
import sys
import time

# ---------------------------------------------------------------------------
# Ensure ida-python site-packages is on sys.path.
# When IDA is launched with -A (autonomous mode), the embedded Python may not
# include ida-python/Lib/site-packages in its sys.path.  The launcher passes
# the path via IDAMCP_PYTHONPATH; the plugin reads it here and calls
# site.addsitedir() to also process .pth files (e.g. pywin32.pth).
# This must run before any third-party imports (fastmcp, etc.).
# ---------------------------------------------------------------------------
_sp = os.environ.get("IDAMCP_PYTHONPATH")
if not _sp:
    # Derive from config.conf ida_python setting.
    try:
        from ida_mcp.config import get_ida_python as _get_ida_python

        _ida_python_conf = _get_ida_python()
        if _ida_python_conf:
            _sp = os.path.join(os.path.dirname(_ida_python_conf), "Lib", "site-packages")
    except Exception:
        pass
if not _sp:
    # Fallback: ida-python sibling of the IDA executable directory.
    _sp = os.path.join(
        os.path.dirname(os.path.abspath(sys.executable)), "ida-python", "Lib", "site-packages"
    )
if os.path.isdir(_sp) and _sp not in sys.path:
    _site.addsitedir(_sp)

import idaapi  # type: ignore
import ida_kernwin  # type: ignore

from ida_mcp import plugin_runtime
from ida_mcp.config import (
    get_ida_default_port,
    get_ida_host,
    is_auto_start_enabled,
    is_stdio_enabled,
    is_http_enabled,
)


def _warmup_caches():
    """后台预构建字符串缓存，避免首次 list_strings 调用超时。

    使用 execute_sync(MFF_READ) 确保在 IDA 主线程执行 idautils.Strings()，
    但通过守护线程调度，不阻塞当前 UI 操作。
    """

    def _do_warmup():
        try:
            from ida_mcp.api_core import init_caches

            ida_kernwin.execute_sync(
                lambda: (init_caches(), 0)[1], ida_kernwin.MFF_READ
            )
        except Exception as e:
            plugin_runtime._info(f"Cache warmup failed (non-fatal): {e}")

    t = threading.Thread(target=_do_warmup, name="IDA-MCP-CacheWarmup", daemon=True)
    t.start()


def _main_thread_tick_loop() -> None:
    while not plugin_runtime._tick_stop_event.is_set():
        try:
            if ida_kernwin and hasattr(ida_kernwin, "execute_sync"):
                ida_kernwin.execute_sync(lambda: 0, ida_kernwin.MFF_READ)  # type: ignore[arg-type]
                plugin_runtime.set_main_thread_tick()
        except Exception:
            pass
        plugin_runtime._tick_stop_event.wait(plugin_runtime._MAIN_THREAD_TICK_INTERVAL)


def _prime_path_caches():
    """在 IDA 主线程捕获输入文件/IDB 路径缓存。"""
    if idaapi is None:
        return

    cached_input_file = plugin_runtime._cached_input_file
    cached_idb_path = plugin_runtime._cached_idb_path
    if cached_input_file is not None and (
        cached_idb_path is not None or not hasattr(idaapi, "get_path")
    ):
        return

    def _capture() -> int:
        input_file = plugin_runtime._cached_input_file
        idb_path = plugin_runtime._cached_idb_path
        if input_file is None:
            try:
                input_file = getattr(
                    idaapi, "get_input_file_path", lambda: None
                )()  # type: ignore
            except Exception:
                input_file = None
        if idb_path is None and hasattr(idaapi, "get_path"):
            try:
                idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)  # type: ignore
            except Exception:
                idb_path = None
        plugin_runtime.set_path_cache(input_file, idb_path)
        return 0

    try:
        if ida_kernwin and hasattr(ida_kernwin, "execute_sync"):
            ida_kernwin.execute_sync(_capture, ida_kernwin.MFF_READ)  # type: ignore
        else:
            _capture()
    except Exception:
        try:
            _capture()
        except Exception:
            pass


plugin_runtime.register_host_callbacks(
    tick_loop_fn=_main_thread_tick_loop,
    prime_paths_fn=_prime_path_caches,
)


def PLUGIN_ENTRY():  # IDA looks for this symbol
    return IDAMCPPlugin()


class IDAMCPPlugin(idaapi.plugin_t if idaapi else object):  # type: ignore
    flags = 0
    comment = "FastMCP HTTP server for IDA"
    help = "Expose IDA features through Model Context Protocol"
    wanted_name = "IDA-MCP"
    wanted_hotkey = ""

    def init(self):  # type: ignore
        if idaapi is None:
            plugin_runtime._warn("Outside IDA environment; plugin inactive.")
            return idaapi.PLUGIN_SKIP if idaapi else 0

        bootstrap_auto_start = os.getenv("IDA_MCP_AUTO_START") == "1"
        if bootstrap_auto_start or is_auto_start_enabled():
            reason = (
                "IDA_MCP_AUTO_START=1"
                if bootstrap_auto_start
                else "config auto_start=true"
            )
            plugin_runtime._info(f"Auto-starting server due to {reason}")

            # 延迟一小段时间启动，确保 IDA 核心已就绪
            def _auto():
                time.sleep(1)
                if not plugin_runtime.is_running():
                    host = get_ida_host()
                    port = plugin_runtime._select_start_port(host)
                    _prime_path_caches()
                    plugin_runtime.start_server_async(host, port)

            t = threading.Thread(target=_auto, daemon=True)
            t.start()
        else:
            # 不自动启动, 等待用户菜单/快捷方式显式触发。
            plugin_runtime._info("Plugin initialized and ready (not auto-starting).")
        return idaapi.PLUGIN_KEEP  # type: ignore

    def run(self, arg):  # type: ignore
        # 切换行为: 运行中 -> 停止; 否则启动。仅打印日志, 不弹出对话框。
        if not idaapi:
            plugin_runtime._warn("Run invoked but not inside IDA.")
            return
        if plugin_runtime.is_running():
            plugin_runtime._info("Server running -> toggling to stop.")
            plugin_runtime.stop_server()
            return
        # 检查传输方式配置
        stdio_enabled = is_stdio_enabled()
        http_enabled = is_http_enabled()
        if not stdio_enabled and not http_enabled:
            plugin_runtime._warn(
                "Both stdio and HTTP modes are disabled in config.conf. No server started."
            )
            return
        # 显示启用的传输方式
        modes = []
        if stdio_enabled:
            modes.append("stdio")
        if http_enabled:
            modes.append("HTTP")
        plugin_runtime._info(f"Transport modes enabled: {', '.join(modes)}")
        host = get_ida_host()
        # 端口选择: 若 launcher 注入 IDA_MCP_PORT，则以其为起点继续向上探测
        # 必须使用实际监听地址进行端口探测
        port = plugin_runtime._select_start_port(host)
        plugin_runtime._info(
            f"Preparing MCP startup for http://{host}:{port}/mcp/ "
            "(gateway preflight first; toggle to stop)"
        )
        _prime_path_caches()
        plugin_runtime.start_server_async(host, port)
        # 在后台预构建字符串缓存，避免首次 list_strings 调用超时
        _warmup_caches()

    def term(self):  # type: ignore
        plugin_runtime._info("Plugin terminating.")
        if plugin_runtime.is_running():
            plugin_runtime.stop_server()


if __name__ == "__main__":
    plugin_runtime._info("Standalone mode: starting server.")
    _prime_path_caches()
    plugin_runtime.start_server_async(get_ida_host(), get_ida_default_port())
    if plugin_runtime._startup_thread:
        plugin_runtime._startup_thread.join()
    if plugin_runtime._server_thread:
        plugin_runtime._server_thread.join()
