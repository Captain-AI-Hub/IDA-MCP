import os
import socket
import threading
import time
import traceback

from ida_mcp import registry
from ida_mcp.config import (
    get_gateway_internal_host,
    get_gateway_internal_port,
    get_http_bind_host,
    get_http_path,
    get_http_port,
    get_ida_default_port,
    get_server_name,
    is_http_enabled,
    is_unsafe_enabled,
)
from ida_mcp.runtime import start_http_proxy_if_gateway
from ida_mcp.server_factory import create_mcp_server

_server_thread: threading.Thread | None = (
    None  # 后台 uvicorn 线程 (运行 FastMCP ASGI 服务)
)
_uv_server = None  # type: ignore               # uvicorn.Server 实例引用, 用于优雅关闭 (should_exit)
_startup_thread: threading.Thread | None = (
    None  # 启动预检线程 (先确认 gateway 健康, 再启动实例 listener)
)
_startup_stop = threading.Event()  # 启动预检取消信号 (stop_server 中置位)
_stop_lock = threading.Lock()  # 防止 stop_server 并发重入的互斥锁
_active_port: int | None = None  # 当前实例实际监听的 MCP 端口 (启动后写入, 停止时清空)
_hb_thread: threading.Thread | None = (
    None  # 心跳/保活线程对象 (负责检测协调器状态与定期刷新注册)
)
_hb_stop = threading.Event()  # 心跳线程停止信号 (stop_server 中置位)
_tick_thread: threading.Thread | None = None
_tick_stop_event = threading.Event()
_last_register_ts: float | None = (
    None  # 最近一次成功调用 registry.init_and_register 的时间戳 (仅在缺失后重注册时更新)
)
_ENABLE_PERIODIC_REFRESH = (
    False  # 设为 True 才会启用“超时周期刷新”逻辑，默认只在缺失时重注册
)
_REGISTER_INTERVAL = 300  # (可选) 原本用于周期 refresh 的阈值; 默认禁用
_HEARTBEAT_INTERVAL = 5  # 心跳循环唤醒/巡检间隔
_HEARTBEAT_WARN_INTERVAL = 300  # 心跳连续失败时，重复告警的最小间隔
_cached_input_file: str | None = (
    None  # 缓存的输入二进制路径 (仅主线程初始化; 心跳线程避免直接调用 IDA API)
)
_cached_idb_path: str | None = (
    None  # 缓存的 IDB 路径 (同上, 避免后台线程访问 IDA C 接口)
)
_hb_failure_count = 0  # 连续 heartbeat 重注册失败次数
_hb_last_failure_sig: str | None = None  # 最近一次 heartbeat 失败签名
_hb_last_warn_ts = 0.0  # 最近一次 heartbeat 告警时间
_last_main_thread_tick_at: float | None = None
_MAIN_THREAD_TICK_INTERVAL = 5.0

_host_tick_fn = None
_host_prime_paths = None


def register_host_callbacks(*, tick_loop_fn=None, prime_paths_fn=None):
    global _host_tick_fn, _host_prime_paths
    if tick_loop_fn is not None:
        _host_tick_fn = tick_loop_fn
    if prime_paths_fn is not None:
        _host_prime_paths = prime_paths_fn


def set_path_cache(input_file, idb_path):
    global _cached_input_file, _cached_idb_path
    _cached_input_file = input_file
    _cached_idb_path = idb_path


def set_main_thread_tick(ts=None):
    global _last_main_thread_tick_at
    _last_main_thread_tick_at = time.time() if ts is None else ts


def start_tick_thread() -> None:
    global _tick_thread
    set_main_thread_tick()
    if _tick_thread is not None and _tick_thread.is_alive():
        return
    _tick_stop_event.clear()
    if _host_tick_fn is None:
        return
    _tick_thread = threading.Thread(
        target=_host_tick_fn,
        name="IDA-MCP-MainThreadTick",
        daemon=True,
    )
    _tick_thread.start()


def _wait_for_server_start(ready_event: threading.Event, server_obj) -> None:
    """等待 uvicorn 将 started 标志置为 True。"""
    try:
        for _ in range(100):
            if getattr(server_obj, "started", False):
                ready_event.set()
                return
            if getattr(server_obj, "should_exit", False):
                return
            time.sleep(0.05)
    except Exception:
        return


def _port_is_listening(host: str, port: int, timeout: float = 0.2) -> bool:
    """Check whether the MCP HTTP listener is already accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _complete_startup_in_background(
    host: str,
    port: int,
    server_ready: threading.Event,
    server_failed: threading.Event,
) -> None:
    """Finish registration after the HTTP listener is ready without blocking the UI thread."""
    start_ts = time.monotonic()
    warned_slow = False
    while True:
        if _uv_server is not None and getattr(_uv_server, "should_exit", False):
            return
        if server_ready.is_set() or _port_is_listening(host, port):
            break
        if server_failed.is_set() or not (_server_thread and _server_thread.is_alive()):
            _error(f"Server failed before bind on {host}:{port}")
            return
        if not warned_slow and (time.monotonic() - start_ts) >= 5.0:
            warned_slow = True
            _warn(
                f"Server startup is taking longer than expected on {host}:{port}; registration continues in background."
            )
        time.sleep(0.1)

    # Only mark the instance as active after gateway registration succeeds.
    global _active_port
    if _active_port == port:
        return
    if _uv_server is not None and getattr(_uv_server, "should_exit", False):
        return
    _info(
        f"Instance MCP listener is ready at http://{host}:{port}/mcp/; "
        "registering with gateway."
    )
    if not _register_with_coordinator(port):
        _warn(
            f"Instance MCP server is listening on {host}:{port}, but gateway registration is incomplete."
        )
        return
    _active_port = port
    start_tick_thread()
    # 记录注册时间并启动心跳线程
    global _hb_thread, _last_register_ts
    _last_register_ts = time.time()
    if _hb_thread is None or not _hb_thread.is_alive():
        _hb_stop.clear()
        _hb_thread = threading.Thread(
            target=_heartbeat_loop, name="IDA-MCP-Heartbeat", daemon=True
        )
        _hb_thread.start()
        _info("Heartbeat thread started.")


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
        tick_at = _last_main_thread_tick_at
        tick_lag = None if tick_at is None else max(time.time() - tick_at, 0.0)
        if _active_port is not None:
            try:
                registry.update_instance_status(
                    pid=pid,
                    port=_active_port,
                    lifecycle_state="ready",
                    ready=True,
                    main_thread_last_tick_at=tick_at,
                    main_thread_lag_seconds=tick_lag,
                )
            except Exception:
                pass
        need_register = False
        now = time.time()
        if not inst_list:
            need_register = True
        else:
            found = any(e.get("pid") == pid for e in inst_list)
            if not found:
                need_register = True
        # 不再默认进行“时间驱动的强制 refresh”，仅在实例缺失或协调器重建时重注册。
        if (
            not need_register
            and _ENABLE_PERIODIC_REFRESH
            and _last_register_ts
            and (now - _last_register_ts) > _REGISTER_INTERVAL
        ):
            need_register = True  # 可选：用户显式启用时恢复旧逻辑
        if need_register and _active_port is not None:
            try:
                # 仅用缓存的路径/文件, 避免后台线程再触碰 IDA API
                registry.init_and_register(
                    _active_port, _cached_input_file, _cached_idb_path
                )
                registry.update_instance_status(
                    pid=pid,
                    port=_active_port,
                    lifecycle_state="ready",
                    ready=True,
                    main_thread_last_tick_at=tick_at,
                    main_thread_lag_seconds=tick_lag,
                )
                _last_register_ts = now
                _reset_heartbeat_failure_tracking(log_recovery=True)
                if inst_list:
                    _info(
                        "Heartbeat re-register (periodic refresh) done."
                    ) if _ENABLE_PERIODIC_REFRESH else None
                else:
                    _info(
                        "Heartbeat re-register successful (gateway rebuilt or entry missing)."
                    )
            except Exception as e:  # pragma: no cover
                _report_heartbeat_failure(str(e))
        _hb_stop.wait(_HEARTBEAT_INTERVAL)
    _info("Heartbeat thread exit.")


# ---------------- Logging Helpers (INFO/WARN/ERROR) -----------------


def _now_ts() -> str:
    return time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"


def _log(level: str, msg: str):
    """Unified log output with timestamp (HH:MM:SS.mmm)."""
    print(f"[IDA-MCP][{level}][{_now_ts()}] {msg}")


def _info(msg: str):
    _log("INFO", msg)


def _warn(msg: str):
    _log("WARN", msg)


def _error(msg: str):
    _log("ERROR", msg)


def _gateway_diagnostics_text() -> str:
    """Summarize gateway launch diagnostics for IDA main-log output."""
    status_getter = getattr(registry, "get_registry_server_status", None)
    if not callable(status_getter):
        return ""
    try:
        status = status_getter() or {}
    except Exception:
        return ""

    parts = []
    if status.get("python"):
        parts.append(f"python={status['python']}")
    if status.get("log"):
        parts.append(f"log={status['log']}")
    if status.get("last_error"):
        parts.append(f"last_error={status['last_error']}")
    return ", ".join(parts)


def _report_heartbeat_failure(error_text: str) -> None:
    """Throttle repeated heartbeat registration failures in the main log."""
    global _hb_failure_count, _hb_last_failure_sig, _hb_last_warn_ts

    now = time.time()
    repeated = error_text == _hb_last_failure_sig
    _hb_failure_count += 1
    should_warn = (
        _hb_failure_count == 1
        or not repeated
        or (now - _hb_last_warn_ts) >= _HEARTBEAT_WARN_INTERVAL
    )
    if not should_warn:
        return

    suppressed = _hb_failure_count - 1
    prefix = "Heartbeat re-register failed"
    if suppressed > 0:
        prefix += f" ({suppressed} similar failure(s) suppressed)"
    _warn(f"{prefix}: {error_text}")
    _hb_last_failure_sig = error_text
    _hb_last_warn_ts = now


def _reset_heartbeat_failure_tracking(log_recovery: bool = False) -> None:
    """Clear heartbeat failure throttling state after success or shutdown."""
    global _hb_failure_count, _hb_last_failure_sig, _hb_last_warn_ts
    if log_recovery and _hb_failure_count > 0:
        _info(
            f"Heartbeat re-register recovered after {_hb_failure_count} consecutive failure(s)."
        )
    _hb_failure_count = 0
    _hb_last_failure_sig = None
    _hb_last_warn_ts = 0.0


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


def _select_start_port(host: str) -> int:
    """Select a bindable MCP port, treating bootstrap IDA_MCP_PORT as a preferred starting point."""
    env_port = os.getenv("IDA_MCP_PORT")
    if env_port and env_port.isdigit():
        return _find_free_port(int(env_port), host)
    return _find_free_port(get_ida_default_port(), host)


def _ensure_gateway_ready_for_startup() -> bool:
    """Confirm the standalone gateway is healthy before exposing the instance listener."""
    gateway_host = get_gateway_internal_host()
    gateway_port = get_gateway_internal_port()
    _info(
        f"Checking gateway health at {gateway_host}:{gateway_port} before starting instance MCP listener."
    )
    if registry.ensure_registry_server():
        _info(
            f"Gateway is healthy at {gateway_host}:{gateway_port}; continuing instance startup."
        )
        return True

    _error(
        f"Gateway preflight failed at {gateway_host}:{gateway_port}; "
        "instance MCP listener will not be started."
    )
    diag = _gateway_diagnostics_text()
    if diag:
        _error(f"Gateway diagnostics: {diag}")
    return False


def _register_with_coordinator(port: int) -> bool:
    """向协调器注册当前实例元信息。

    参数:
        port: 当前实例 FastMCP HTTP 监听端口。
    说明:
        * 若独立协调器/HTTP proxy 尚未运行，会按需拉起。
        * 注册内容包括: pid / port / 输入文件路径 / idb 路径 / Python 版本等。
    """
    global _cached_input_file, _cached_idb_path
    if _host_prime_paths:
        _host_prime_paths()
    try:
        registry.init_and_register(port, _cached_input_file, _cached_idb_path)
        http_proxy_ready = start_http_proxy_if_gateway()
        _reset_heartbeat_failure_tracking()
        _info(
            f"Registered instance at port={port} pid={os.getpid()} input='{_cached_input_file}' idb='{_cached_idb_path}'"
        )
        if http_proxy_ready:
            _info(
                f"HTTP MCP proxy listening on "
                f"http://{get_http_bind_host()}:{get_http_port()}{get_http_path()}"
            )
        elif is_http_enabled():
            proxy_status = getattr(registry, "get_http_proxy_status", lambda: {})()
            status_parts = []
            if proxy_status.get("python"):
                status_parts.append(f"python={proxy_status['python']}")
            if proxy_status.get("log"):
                status_parts.append(f"log={proxy_status['log']}")
            if proxy_status.get("last_error"):
                status_parts.append(f"last_error={proxy_status['last_error']}")
            suffix = f" ({', '.join(status_parts)})" if status_parts else ""
            _warn(f"HTTP MCP proxy launch requested but not yet reachable{suffix}")
        gateway_suffix = get_http_path() if is_http_enabled() else ""
        _info(
            f"Gateway listening on {get_http_bind_host()}:{get_http_port()}{gateway_suffix}"
        )
        return True
    except Exception as e:  # pragma: no cover
        _error(f"Gateway registration failed: {e}")
        diag = _gateway_diagnostics_text()
        if diag:
            _error(f"Gateway diagnostics: {diag}")
        traceback.print_exc()
        return False


def _update_lifecycle_state(port: int, state: str, ready: bool) -> None:
    try:
        registry.update_instance_status(
            pid=os.getpid(),
            port=port,
            lifecycle_state=state,
            ready=ready,
        )
    except Exception:
        pass


def is_running() -> bool:
    return (_startup_thread is not None and _startup_thread.is_alive()) or (
        _server_thread is not None and _server_thread.is_alive()
    )


def stop_server():
    """停止服务器 (切换)。

    步骤:
        1. 设置 ``_uv_server.should_exit`` 触发 uvicorn 事件循环退出。
        2. join 后台线程 (最多 5 秒)。
        3. 向独立协调器注销当前实例。
    并发安全:
        使用 ``_stop_lock`` 以防多次同时调用。
    """
    global _startup_thread, _uv_server, _server_thread
    with _stop_lock:
        startup_thread = _startup_thread
        startup_active = startup_thread is not None and startup_thread.is_alive()
        if _uv_server is None and not startup_active:
            _info("Stop requested, but server not running.")
            return
        if startup_active:
            _startup_stop.set()
            _info("Startup cancellation requested.")
        try:
            # Graceful shutdown
            if _uv_server is not None:
                _uv_server.should_exit = True  # type: ignore[attr-defined]
                _info("Shutdown signal sent to uvicorn server.")
        except Exception as e:  # pragma: no cover
            _error(f"Failed to signal shutdown: {e}")
        if startup_thread:
            startup_thread.join(timeout=5)
            if not startup_thread.is_alive():
                _startup_thread = None
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
        global _hb_thread, _tick_thread, _last_main_thread_tick_at
        if _hb_thread and _hb_thread.is_alive():
            _hb_stop.set()
            _hb_thread.join(timeout=3)
        _hb_thread = None
        if _tick_thread and _tick_thread.is_alive():
            _tick_stop_event.set()
            _tick_thread.join(timeout=1)
        _tick_thread = None
        _last_main_thread_tick_at = None
        _reset_heartbeat_failure_tracking()
        _info("Server stopped.")


def _start_instance_server_threads(host: str, port: int) -> None:
    """Launch the instance uvicorn worker only after gateway preflight has passed."""
    global _server_thread, _uv_server
    server_ready = threading.Event()
    server_failed = threading.Event()

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
                        asyncio.set_event_loop_policy(
                            asyncio.WindowsSelectorEventLoopPolicy()
                        )  # type: ignore[attr-defined]
                except Exception:
                    pass  # 策略设置失败时不影响后续逻辑，最多产生原有控制台提示
            server = create_mcp_server(
                name=get_server_name(),
                enable_unsafe=is_unsafe_enabled(),
            )
            # 构建 ASGI 应用 (Streamable HTTP), 挂载路径 '/mcp'
            app = server.http_app(path="/mcp")  # type: ignore[attr-defined]
            # 在导入 uvicorn 之前再次确保过滤器生效
            import warnings as _w

            _w.filterwarnings(
                "ignore", category=DeprecationWarning, module=r"websockets"
            )
            _w.filterwarnings("ignore", category=DeprecationWarning, module=r"uvicorn")
            import uvicorn  # Local import to avoid overhead if never started

            # 使用 warning 日志级别并关闭 access log, 避免输出无意义的 CTRL+C 提示。
            config = uvicorn.Config(
                app, host=host, port=port, log_level="warning", access_log=False
            )
            _uv_server = uvicorn.Server(config)
            # 不使用 uvicorn.Server.run()（其内部会创建/管理事件循环），
            # 我们在此线程内显式创建 loop 并安装异常处理器，以抑制
            # Windows 下常见的 WinError 10054 “远程主机强迫关闭连接”噪音。
            import asyncio

            def _exception_handler(loop, context):  # type: ignore[no-untyped-def]
                exc = context.get("exception")
                if exc is not None:
                    winerr = getattr(exc, "winerror", None)
                    if winerr == 10054 and isinstance(
                        exc, (ConnectionResetError, OSError)
                    ):
                        return
                msg = str(context.get("message") or "")
                if "10054" in msg and "ConnectionResetError" in msg:
                    return
                loop.default_exception_handler(context)

            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                loop.set_exception_handler(_exception_handler)
                threading.Thread(
                    target=_wait_for_server_start,
                    args=(server_ready, _uv_server),
                    name="IDA-MCP-ServerReady",
                    daemon=True,
                ).start()
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
            server_failed.set()
            _error(f"Server crashed: {e}")
            traceback.print_exc()
        finally:
            _uv_server = None
            _info("Server thread exit.")

    _server_thread = threading.Thread(target=worker, name="IDA-MCP-Server", daemon=True)
    _server_thread.start()
    threading.Thread(
        target=_complete_startup_in_background,
        args=(host, port, server_ready, server_failed),
        name="IDA-MCP-StartupFinalize",
        daemon=True,
    ).start()


def start_server_async(host: str, port: int):
    """异步(线程)启动 uvicorn FastMCP 服务。

    设计要点:
        * 使用守护线程避免阻塞 IDA 主线程。
        * 在启动实例 listener 之前, 先确认独立 gateway 已就绪, 避免误导用户认为初始化已完成。
        * 通过保存 ``_uv_server`` 引用实现优雅关闭 (设置 should_exit)。
        * 仅在实例 MCP 端口确认监听成功后向协调器注册。
    """
    global _startup_thread
    if is_running():
        _info("Server already running; start request ignored.")
        return

    _startup_stop.clear()

    def bootstrap():
        global _startup_thread
        try:
            if _startup_stop.is_set():
                return
            if not _ensure_gateway_ready_for_startup():
                return
            _update_lifecycle_state(port, "analyzing", ready=False)
            if _startup_stop.is_set():
                _info("Startup cancelled before instance MCP listener launch.")
                return
            _info(
                f"Gateway preflight complete; starting instance MCP listener at http://{host}:{port}/mcp/"
            )
            _start_instance_server_threads(host, port)
        finally:
            _startup_thread = None

    _startup_thread = threading.Thread(
        target=bootstrap, name="IDA-MCP-Startup", daemon=True
    )
    _startup_thread.start()
