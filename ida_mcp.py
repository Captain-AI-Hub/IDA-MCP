"""IDA Pro MCP 插件（JSON-RPC 桥 + 共享实例清单）

功能综述
====================
在每个 IDA 进程内运行一个纯标准库 **JSON-RPC 桥**，把 ``ida_mcp/api_*.py``
的工具与 ``ida://`` 资源暴露给独立的 MCP 服务器进程（stdio 默认 / http 可选），
并把本实例登记到共享 JSON 清单（``<IDAUSR>/ida-mcp/instances.json``）。

核心特性:
    1. 启动/关闭采用“切换式”触发（再次运行插件即关闭）。
    2. 打开数据库后桥自动启动（固定 127.0.0.1，无需配置）。
    3. 端口从 13337 起向上扫描；``IDA_MCP_PORT`` 环境变量可指定优先起点
       （由 open_database 启动器注入）。
    4. IDA 进程内零第三方依赖（不再安装 fastmcp/uvicorn 到 IDAPython）。

运行时架构
--------------------
``MCP 客户端`` → ``独立 MCP 服务器`` (uvx idamcp stdio|http) → ``实例桥 (本插件)``
独立服务器通过共享 JSON 清单发现实例，直接调用对应桥，无网关、无端口注册转发。

bootstrap 环境变量 (launcher 内部使用)
--------------------
* ``IDA_MCP_PORT``: 本次启动的优先端口起点。

使用方式
--------------------
1. 将本文件与 ``ida_mcp`` 目录复制到 IDA ``plugins/``（或用 hcli/install.py 安装）。
2. 打开目标二进制，桥自动启动（或通过 Edit ▸ Plugins ▸ IDA-MCP 手动切换）。
3. MCP 客户端配置 ``uvx idamcp stdio``，调用 open_database 附加或无头打开。
"""

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
# site.addsitedir() to also process .pth files.
# ---------------------------------------------------------------------------
_sp = os.environ.get("IDAMCP_PYTHONPATH")
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
from ida_mcp.bridge_server import BRIDGE_HOST
from ida_mcp.config import initialize_runtime_settings


def _warmup_caches():
    """后台预构建字符串缓存，避免首次 list_strings 调用超时。"""

    def _do_warmup():
        try:
            from ida_mcp.api_core import init_caches

            ida_kernwin.execute_sync(
                lambda: (init_caches(), 0)[1], ida_kernwin.MFF_READ
            )
        except Exception as e:
            plugin_runtime._info(f"Cache warmup failed (non-fatal): {e}")

    threading.Thread(target=_do_warmup, name="IDA-MCP-CacheWarmup", daemon=True).start()


def _prime_path_caches():
    """在 IDA 主线程捕获输入文件/IDB 路径缓存。"""

    def _capture() -> int:
        input_file = None
        idb_path = None
        try:
            input_file = idaapi.get_input_file_path()  # type: ignore
        except Exception:
            pass
        try:
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)  # type: ignore
        except Exception:
            pass
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


plugin_runtime.register_host_callbacks(prime_paths_fn=_prime_path_caches)


def PLUGIN_ENTRY():  # IDA looks for this symbol
    return IDAMCPPlugin()


class IDAMCPPlugin(idaapi.plugin_t if idaapi else object):  # type: ignore
    flags = 0
    comment = "JSON-RPC bridge for IDA-MCP-Hub"
    help = "Expose IDA features through the IDA-MCP bridge"
    wanted_name = "IDA-MCP-Hub"
    wanted_hotkey = ""

    def init(self):  # type: ignore
        if idaapi is None:
            plugin_runtime._warn("Outside IDA environment; plugin inactive.")
            return idaapi.PLUGIN_SKIP if idaapi else 0

        runtime_settings = initialize_runtime_settings()
        detected_python = runtime_settings.get("ida_python")
        if detected_python:
            plugin_runtime._info(f"Effective IDAPython interpreter: {detected_python}")

        # 延迟一小段时间启动，确保 IDA 核心已就绪
        def _auto():
            time.sleep(1)
            if not plugin_runtime.is_running():
                _prime_path_caches()
                plugin_runtime.start_server_async(BRIDGE_HOST)

        threading.Thread(target=_auto, daemon=True).start()
        return idaapi.PLUGIN_KEEP  # type: ignore

    def run(self, arg):  # type: ignore
        # 切换行为: 运行中 -> 停止; 否则启动。
        if not idaapi:
            plugin_runtime._warn("Run invoked but not inside IDA.")
            return
        if plugin_runtime.is_running():
            plugin_runtime._info("Bridge running -> toggling to stop.")
            plugin_runtime.stop_server()
            return
        plugin_runtime._info(
            f"Preparing bridge startup on {BRIDGE_HOST} (toggle again to stop)"
        )
        _prime_path_caches()
        plugin_runtime.start_server_async(BRIDGE_HOST)
        _warmup_caches()

    def term(self):  # type: ignore
        plugin_runtime._info("Plugin terminating.")
        if plugin_runtime.is_running():
            plugin_runtime.stop_server()


if __name__ == "__main__":
    plugin_runtime._info("Standalone mode: starting bridge.")
    _prime_path_caches()
    plugin_runtime.start_server_async(BRIDGE_HOST)
