"""IDA Pro MCP 插件 (HTTP + 多实例协调器注册)

功能综述
====================
本插件为每个启动的 IDA 实例提供一个最小化 **FastMCP HTTP** 服务, 暴露逆向分析能力给支持 MCP 的外部客户端。

核心特性:
    1. 启动/关闭采用"切换式"触发(再次运行插件即关闭)。
    2. 自动选择空闲端口 (从 10000 开始向上扫描), MCP 路径固定为 ``/mcp``。
    3. 首个成功启动的实例会在 ``127.0.0.1:11337`` 上创建一个 **内存型协调器(coordinator)**。
    4. 后续实例向协调器注册, 仅在内存维护实例列表, 不落盘 (避免文件锁 / 清理问题)。
    5. 工具最小化: 仅保留 ``list_functions`` 与 ``instances`` (实例列表)。
    6. 可配合独立进程型代理 ``ida_mcp_proxy.py`` 统一访问多个实例。

运行时架构
--------------------
``IDA 实例 (N 个)`` → 各自运行 uvicorn FastMCP (HTTP) → 向协调器登记元信息(pid, port, input_file 等)。
``协调器`` 负责: 记录活跃实例; 接收代理或其他客户端的 /call 请求并转发至目标实例。

线程与生命周期
--------------------
* uvicorn 服务器在 **后台守护线程** 中运行, 便于主线程继续响应 IDA 事件。
* 关闭流程: 设置 ``_uv_server.should_exit = True`` → 等待线程退出 → 调用协调器注销。
* IDA 退出或插件终止时, 若仍在运行则自动停止并反注册。

端口选择策略
--------------------
* 若设置环境变量 ``IDA_MCP_PORT`` 且合法, 则使用该端口 (不再扫描)。
* 否则从 ``DEFAULT_PORT (=10000)`` 起向上扫描 (最大 50 次)。
* 允许多个 IDA 实例并行, 避免端口冲突。

环境变量 (可选)
--------------------
* ``IDA_MCP_PORT``: 指定固定端口。
* ``IDA_MCP_HOST``: 监听地址, 默认 ``127.0.0.1``。
* ``IDA_MCP_NAME``: MCP 服务名, 默认 ``IDA-MCP``。

主要内部变量
--------------------
* ``_server_thread``: 后台 uvicorn 线程对象。
* ``_uv_server``: uvicorn Server 实例 (用于发出停止信号)。
* ``_active_port``: 当前实例实际使用端口。
* ``_stop_lock``: 防止并发关闭竞争。

公共函数概览
--------------------
* ``start_server_async(host, port)``: 启动 MCP 服务器 (线程)。
* ``stop_server()``: 发送退出信号并等待线程结束, 注销协调器。
* ``is_running()``: 判断当前服务器线程是否存活。

扩展建议
--------------------
未来可在 ``ida_mcp/server.py`` 内增量添加更多工具 (反编译、交叉引用、数据段搜索等)。协调器 ``registry.py`` 已支持 /call 转发, 添加工具仅需在每个实例服务端注册, 代理端(可选)补一层转发包装。

使用方式
--------------------
1. 将本文件与 ``ida_mcp`` 目录复制到 IDA ``plugins/``。
2. 打开目标二进制, 分析完成后在菜单或快捷键中执行插件 (第一次执行 = 启动)。
3. 再次执行插件 = 停止并反注册。
4. 可启动多个 IDA 实例重复步骤 2, 通过协调器配合代理统一访问。

调试提示
--------------------
* 如果端口被占用, 会自动向上扫描; 如全部失败, 仍可能抛出绑定异常 (检查是否被防火墙或安全软件占用)。
* 服务器崩溃日志会打印堆栈; 若需更详细日志可将 uvicorn log_level 改为 info/debug。

本文件只包含逻辑入口与生命周期管理, 实际工具定义在 ``ida_mcp/server.py``。
"""

import warnings
# 必须在任何可能导入 websockets 的模块之前设置过滤器
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"websockets\..*")
warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*websockets.*")

import threading
import os
import traceback
import socket
import time

import idaapi  # type: ignore
import ida_kernwin  # type: ignore

from ida_mcp import create_mcp_server, DEFAULT_PORT, registry
from ida_mcp.config import (
    get_ida_host, get_coordinator_host, get_coordinator_port,
    is_stdio_enabled, is_http_enabled
)

_server_thread: threading.Thread | None = None  # 后台 uvicorn 线程 (运行 FastMCP ASGI 服务)
_uv_server = None  # type: ignore               # uvicorn.Server 实例引用, 用于优雅关闭 (should_exit)
_stop_lock = threading.Lock()                   # 防止 stop_server 并发重入的互斥锁
_active_port: int | None = None                 # 当前实例实际监听的 MCP 端口 (启动后写入, 停止时清空)
_hb_thread: threading.Thread | None = None      # 心跳/保活线程对象 (负责检测协调器状态与定期刷新注册)
_hb_stop = threading.Event()                    # 心跳线程停止信号 (stop_server 中置位)
_last_register_ts: float | None = None          # 最近一次成功调用 registry.init_and_register 的时间戳 (仅在缺失后重注册时更新)
_ENABLE_PERIODIC_REFRESH = False                # 设为 True 才会启用“超时周期刷新”逻辑，默认只在缺失时重注册
_REGISTER_INTERVAL = 300                        # (可选) 原本用于周期 refresh 的阈值; 默认禁用
_HEARTBEAT_INTERVAL = 60                        # 心跳循环唤醒/巡检间隔
_cached_input_file: str | None = None           # 缓存的输入二进制路径 (仅主线程初始化; 心跳线程避免直接调用 IDA API)
_cached_idb_path: str | None = None             # 缓存的 IDB 路径 (同上, 避免后台线程访问 IDA C 接口)


def _warmup_caches():
    """后台预构建字符串缓存，避免首次 list_strings 调用超时。
    
    使用 execute_sync(MFF_READ) 确保在 IDA 主线程执行 idautils.Strings()，
    但通过守护线程调度，不阻塞当前 UI 操作。
    """
    def _do_warmup():
        try:
            from ida_mcp.api_core import init_caches
            ida_kernwin.execute_sync(lambda: (init_caches(), 0)[1], ida_kernwin.MFF_READ)
        except Exception as e:
            _info(f"Cache warmup failed (non-fatal): {e}")
    
    t = threading.Thread(target=_do_warmup, name="IDA-MCP-CacheWarmup", daemon=True)
    t.start()

def _heartbeat_loop():
    """后台心跳: 定期确认协调器仍可访问且本实例记录存在, 否则重新注册。

    触发条件:
        * 协调器列表为空 (所有实例丢失) -> 重新注册 (可能重建协调器)
        * 本实例 pid 未出现在 get_instances() 结果中 -> 重新注册
        * 正常情况下每 _REGISTER_INTERVAL 秒做一次 refresh (覆盖 started 时间, 保持活跃)

    设计考量:
        * registry 当前无心跳超时机制, 但某些情况下协调器线程可能被系统/异常终止。
        * 使用轻量轮询, 避免对 IDA 主线程的调用; 仅访问 registry (纯网络/内存操作)。
        * 若服务器已停止 (_active_port 为空) 则直接退出。
    """
    global _last_register_ts
    pid = os.getpid()
    
    # 等待服务器初始化完成 (最多 10 秒)
    for _ in range(20):
        if _hb_stop.is_set():
            _info("Heartbeat thread exit (stop signal during startup).")
            return
        if _uv_server is not None:
            break
        time.sleep(0.5)
    
    while not _hb_stop.is_set():
        # 若服务已经关闭, 退出
        if _active_port is None:
            break
        # 服务器可能在重启中，跳过本轮检查
        if _uv_server is None:
            _hb_stop.wait(_HEARTBEAT_INTERVAL)
            continue
        try:
            inst_list = registry.get_instances()
        except Exception:
            inst_list = []
        need_register = False
        now = time.time()
        if not inst_list:
            need_register = True
        else:
            found = any(e.get('pid') == pid for e in inst_list)
            if not found:
                need_register = True
        # 不再默认进行“时间驱动的强制 refresh”，仅在实例缺失或协调器重建时重注册。
        if (not need_register and _ENABLE_PERIODIC_REFRESH and _last_register_ts
                and (now - _last_register_ts) > _REGISTER_INTERVAL):
            need_register = True  # 可选：用户显式启用时恢复旧逻辑
        if need_register and _active_port is not None:
            try:
                # 仅用缓存的路径/文件, 避免后台线程再触碰 IDA API
                registry.init_and_register(_active_port, _cached_input_file, _cached_idb_path)
                _last_register_ts = now
                if inst_list:
                    _info("Heartbeat re-register (periodic refresh) done.") if _ENABLE_PERIODIC_REFRESH else None
                else:
                    _info("Heartbeat re-register successful (coordinator rebuilt or entry missing).")
            except Exception as e:  # pragma: no cover
                _warn(f"Heartbeat re-register failed: {e}")
        _hb_stop.wait(_HEARTBEAT_INTERVAL)
    _info("Heartbeat thread exit.")

# ---------------- Logging Helpers (INFO/WARN/ERROR) -----------------

def _now_ts() -> str:
    return time.strftime("%H:%M:%S") + f".{int(time.time()*1000)%1000:03d}"

def _log(level: str, msg: str):
    """Unified log output with timestamp (HH:MM:SS.mmm)."""
    print(f"[IDA-MCP][{level}][{_now_ts()}] {msg}")

def _info(msg: str):
    _log("INFO", msg)

def _warn(msg: str):
    _log("WARN", msg)

def _error(msg: str):
    _log("ERROR", msg)


def _find_free_port(preferred: int, host: str = "127.0.0.1", max_scan: int = 50) -> int:
    """端口扫描: 从 preferred 起向上尝试绑定, 返回第一个可用端口;
    若全部失败则返回 preferred (保底)。
    
    参数:
        preferred: 起始端口号
        host: 要绑定的地址（必须与实际监听地址一致）
        max_scan: 最大扫描次数
    
    注意: 默认端口选择 9000 以避开 Windows Hyper-V 保留端口范围 (8709-8808)。
    不使用 SO_REUSEADDR, 因为在 Windows 上它的行为类似 SO_REUSEPORT。
    """
    for i in range(max_scan):
        p = preferred + i
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
            except OSError:
                continue
            return p
    _warn(f"Port scan exhausted; falling back to preferred {preferred}")
    return preferred


def _register_with_coordinator(port: int):
    """向协调器注册当前实例元信息。

    参数:
        port: 当前实例 FastMCP HTTP 监听端口。
    说明:
        * 首个实例若发现协调器端口空闲会由 registry 内部启动协调器。
        * 注册内容包括: pid / port / 输入文件路径 / idb 路径 / Python 版本等。
    """
    if idaapi is None:
        return
    global _cached_input_file, _cached_idb_path
    if _cached_input_file is None:
        _cached_input_file = getattr(idaapi, 'get_input_file_path', lambda: None)()  # type: ignore
    if _cached_idb_path is None and hasattr(idaapi, 'get_path'):
        try:
            _cached_idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)  # type: ignore
        except Exception:
            _cached_idb_path = None
    try:
        registry.init_and_register(port, _cached_input_file, _cached_idb_path)
        _info(f"Registered instance at port={port} pid={os.getpid()} input='{_cached_input_file}' idb='{_cached_idb_path}'")
        # 若本实例成为协调器, 追加一条提示日志 (用户需求)
        try:
            if getattr(registry, 'is_coordinator', lambda: False)():  # type: ignore[attr-defined]
                _info(f"This instance is COORDINATOR (registry listening on {get_coordinator_host()}:{get_coordinator_port()})")
        except Exception:
            pass
    except Exception as e:  # pragma: no cover
        _error(f"Coordinator registration failed: {e}")
        traceback.print_exc()


def is_running() -> bool:
    return _server_thread is not None and _server_thread.is_alive()


def stop_server():
    """停止服务器 (切换)。

    步骤:
        1. 设置 ``_uv_server.should_exit`` 触发 uvicorn 事件循环退出。
        2. join 后台线程 (最多 5 秒)。
        3. 若已注册协调器则执行注销。
    并发安全:
        使用 ``_stop_lock`` 以防多次同时调用。
    """
    global _uv_server, _server_thread
    with _stop_lock:
        if _uv_server is None:
            _info("Stop requested, but server not running.")
            return
        try:
            # Graceful shutdown
            _uv_server.should_exit = True  # type: ignore[attr-defined]
            _info("Shutdown signal sent to uvicorn server.")
        except Exception as e:  # pragma: no cover
            _error(f"Failed to signal shutdown: {e}")
        if _server_thread:
            # Join server thread with timeout
            _server_thread.join(timeout=5)
        global _active_port
        _server_thread = None
        _uv_server = None
        if _active_port is not None:
            try:
                registry.deregister()
            except Exception as e:  # pragma: no cover
                _warn(f"Deregister failed: {e}")
        _active_port = None
        # 停止心跳线程
        global _hb_thread
        if _hb_thread and _hb_thread.is_alive():
            _hb_stop.set()
            _hb_thread.join(timeout=3)
        _hb_thread = None
        _info("Server stopped.")

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
            _warn("Outside IDA environment; plugin inactive.")
            return idaapi.PLUGIN_SKIP if idaapi else 0
        
        # 注意: 不再全局设置 idaapi.cvar.batch = 1，
        # 因为它会禁用所有UI对话框（包括G键跳转、搜索等）。
        # 写操作时的警告抑制已由 api_modify.py 中的
        # suppress_ida_warnings() 上下文管理器按需临时处理。
        
        # 不自动启动, 等待用户菜单/快捷方式显式触发。
        _info("Plugin initialized and ready (not auto-starting).")
        return idaapi.PLUGIN_KEEP  # type: ignore

    def run(self, arg):  # type: ignore
        # 切换行为: 运行中 -> 停止; 否则启动。仅打印日志, 不弹出对话框。
        if not idaapi:
            _warn("Run invoked but not inside IDA.")
            return
        if is_running():
            _info("Server running -> toggling to stop.")
            stop_server()
            return
        # 检查传输方式配置
        stdio_enabled = is_stdio_enabled()
        http_enabled = is_http_enabled()
        if not stdio_enabled and not http_enabled:
            _warn("Both stdio and HTTP modes are disabled in config.conf. No server started.")
            return
        # 显示启用的传输方式
        modes = []
        if stdio_enabled:
            modes.append("stdio")
        if http_enabled:
            modes.append("HTTP")
        _info(f"Transport modes enabled: {', '.join(modes)}")
        # Host 选择: 优先环境变量，其次 config.conf，最后默认值
        host = os.getenv("IDA_MCP_HOST") or get_ida_host()
        # 端口选择: 优先使用环境变量; 否则自动扫描以支持多实例
        # 必须使用实际监听地址进行端口探测
        env_port = os.getenv("IDA_MCP_PORT")
        if env_port and env_port.isdigit():
            port = int(env_port)
        else:
            port = _find_free_port(DEFAULT_PORT, host)
        _info(f"Starting MCP server at http://{host}:{port}/mcp/ (toggle to stop)")
        start_server_async(host, port)
        # 在后台预构建字符串缓存，避免首次 list_strings 调用超时
        _warmup_caches()

    def term(self):  # type: ignore
        _info("Plugin terminating.")
        if is_running():
            stop_server()

def start_server_async(host: str, port: int):
    """异步(线程)启动 uvicorn FastMCP 服务。

    设计要点:
        * 使用守护线程避免阻塞 IDA 主线程。
        * 通过保存 ``_uv_server`` 引用实现优雅关闭 (设置 should_exit)。
        * 线程启动后立即向协调器注册 (保持实例可发现性)。
    """
    global _server_thread, _uv_server
    if is_running():
        _info("Server already running; start request ignored.")
        return

    def worker():
        global _uv_server
        try:
            # Windows 控制台噪音抑制: 使用 Selector 事件循环替代 Proactor，
            # 规避 asyncio 在 _ProactorBasePipeTransport._call_connection_lost 中
            # 打印的 ConnectionResetError(WinError 10054) 回调异常。
            if os.name == "nt":
                try:
                    import asyncio  # type: ignore
                    if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
                        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined]
                except Exception:
                    pass  # 策略设置失败时不影响后续逻辑，最多产生原有控制台提示
            server = create_mcp_server()
            # 构建 ASGI 应用 (Streamable HTTP), 挂载路径 '/mcp'
            app = server.http_app(path="/mcp")  # type: ignore[attr-defined]
            # 在导入 uvicorn 之前再次确保过滤器生效
            import warnings as _w
            _w.filterwarnings("ignore", category=DeprecationWarning, module=r"websockets")
            _w.filterwarnings("ignore", category=DeprecationWarning, module=r"uvicorn")
            import uvicorn  # Local import to avoid overhead if never started
            # 使用 warning 日志级别并关闭 access log, 避免输出无意义的 CTRL+C 提示。
            config = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
            _uv_server = uvicorn.Server(config)
            # 不使用 uvicorn.Server.run()（其内部会创建/管理事件循环），
            # 我们在此线程内显式创建 loop 并安装异常处理器，以抑制
            # Windows 下常见的 WinError 10054 “远程主机强迫关闭连接”噪音。
            import asyncio

            def _exception_handler(loop, context):  # type: ignore[no-untyped-def]
                exc = context.get("exception")
                if exc is not None:
                    winerr = getattr(exc, "winerror", None)
                    if winerr == 10054 and isinstance(exc, (ConnectionResetError, OSError)):
                        return
                msg = str(context.get("message") or "")
                if "10054" in msg and "ConnectionResetError" in msg:
                    return
                loop.default_exception_handler(context)

            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                loop.set_exception_handler(_exception_handler)
                if hasattr(_uv_server, "serve"):
                    loop.run_until_complete(_uv_server.serve())  # type: ignore[attr-defined]
                else:  # pragma: no cover
                    _uv_server.run()
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                try:
                    loop.run_until_complete(loop.shutdown_default_executor())
                except Exception:
                    pass
                try:
                    loop.close()
                except Exception:
                    pass
        except Exception as e:  # pragma: no cover
            _error(f"Server crashed: {e}")
            traceback.print_exc()
        finally:
            _uv_server = None
            _info("Server thread exit.")

    _server_thread = threading.Thread(target=worker, name="IDA-MCP-Server", daemon=True)
    _server_thread.start()
    # Record chosen port after thread start
    global _active_port
    _active_port = port
    _register_with_coordinator(port)
    # 记录注册时间并启动心跳线程
    global _hb_thread, _last_register_ts
    _last_register_ts = time.time()
    if _hb_thread is None or not _hb_thread.is_alive():
        _hb_stop.clear()
        _hb_thread = threading.Thread(target=_heartbeat_loop, name="IDA-MCP-Heartbeat", daemon=True)
        _hb_thread.start()
        _info("Heartbeat thread started.")

if __name__ == "__main__":
    _info("Standalone mode: starting server.")
    start_server_async("127.0.0.1", DEFAULT_PORT)
    if _server_thread:
        _server_thread.join()
