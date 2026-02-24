"""多实例协调器 (内存) + 工具转发 /call

设计目的
====================
在多个 IDA 实例并行时, 需要一种轻量方式发现彼此并统一转发工具调用。本模块提供一个**内存驻留**的小型 HTTP 服务, 仅占用本地 ``127.0.0.1:11337`` 端口。

角色与职责
--------------------
1. 第一个尝试注册的实例若发现 11337 空闲 → 直接绑定并成为协调器。
2. 其余实例仅向该协调器 POST /register 进行登记。
3. 无任何磁盘持久化; 退出后状态自动丢弃。

HTTP 接口
--------------------
* ``GET  /instances``  : 返回当前注册的全部实例列表 (数组)
* ``POST /register``   : 注册或刷新单个实例 (覆盖 pid 相同的旧记录)
* ``POST /deregister`` : 注销实例 (进程退出 / 插件关闭)
* ``POST /call``       : 将工具调用转发到指定实例 (通过 pid 或 port 识别)

实例结构字段示例
--------------------
```
{
    "pid": 1234,
    "port": 10000,
    "input_file": "/path/to/bin",
    "idb": "/path/to/db.i64",
    "started": 1730000000.123,   # 启动时间戳
    "python": "3.11.9"
}
```

转发机制 (/call)
--------------------
1. 客户端 (或代理) 提交: { tool, params, pid|port }
2. 协调器定位目标实例端口, 使用 fastmcp.Client 临时发起一次真实工具调用。
3. 对返回对象做 “可 JSON 序列化” 处理 (递归转普通结构) 后返回。

并发与线程
--------------------
* 采用 RLock 保护 _instances 列表。
* 协调器 HTTPServer 运行在守护线程, 不阻塞调用方。

扩展建议
--------------------
* 增加心跳(定期刷新时间戳) + 过期清理。
* 增加权限限制 (只允许本地请求 / 简单 token)。
* 支持广播调用 (例如对所有实例同步执行某工具)。

公开辅助函数
--------------------
* ``init_and_register`` : 保证协调器存在并注册当前实例。
* ``get_instances``     : 查询实例列表 (本地 or 远程)。
* ``deregister``        : 注销当前实例。
* ``call_tool``         : 调用 /call 进行一次转发。
"""

from __future__ import annotations
import threading
import json
import time
import socket
import http.server
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
import os
import atexit
import sys
import ida_kernwin  # type: ignore

# 所有内部组件（协调器、IDA 实例）固定使用 127.0.0.1
# 外部访问统一通过 HTTP 代理 (11338)
LOCALHOST = "127.0.0.1"
COORD_HOST = "127.0.0.1"
IDA_HOST = "127.0.0.1"

# 从配置文件加载可配置项
try:
    from .config import (
        get_coordinator_port,
        get_request_timeout,
        is_debug_enabled as _config_debug,
    )
    COORD_PORT = get_coordinator_port()
    REQUEST_TIMEOUT = get_request_timeout()
    DEBUG_ENABLED = _config_debug()
except Exception:
    COORD_PORT = 11337
    REQUEST_TIMEOUT = 30
    DEBUG_ENABLED = False

DEBUG_MAX_LEN = 1000

_instances: List[Dict[str, Any]] = []
_lock = threading.RLock()
_is_coordinator = False
_server_thread: Optional[threading.Thread] = None
_self_pid = os.getpid()
_current_instance_port: Optional[int] = None

# 每个 IDA 实例端口一把锁，序列化对同一实例的并发 /call 请求，
# 防止同时创建多个 MCP session 导致 session manager 崩溃。
_call_locks: Dict[int, threading.Lock] = {}
_call_locks_guard = threading.Lock()

def _short(v: Any) -> str:
    try:
        s = json.dumps(v, ensure_ascii=False)
    except Exception:
        s = str(v)
    if len(s) > DEBUG_MAX_LEN:
        return s[:DEBUG_MAX_LEN] + "..."
    return s

def _debug_log(event: str, **fields: Any):  # pragma: no cover
    if not DEBUG_ENABLED:
        return
    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    kv = ' '.join(f"{k}={_short(v)}" for k, v in fields.items())
    line = f"[{ts}] [registry] {event} {kv}\n"
    try:
        if hasattr(ida_kernwin, 'execute_sync') and hasattr(ida_kernwin, 'msg'):
            def _emit():  # type: ignore
                try:
                    ida_kernwin.msg(line)  # type: ignore
                except Exception:
                    try:
                        print(line, end='')
                    except Exception:
                        pass
                return 0
            try:
                ida_kernwin.execute_sync(_emit, ida_kernwin.MFF_READ)  # type: ignore
            except Exception:
                try:
                    ida_kernwin.msg(line)  # type: ignore
                except Exception:
                    try:
                        print(line, end='')
                    except Exception:
                        pass
        else:
            print(line, end='')
    except Exception:
        pass

def set_debug(enable: bool):
    global DEBUG_ENABLED
    DEBUG_ENABLED = bool(enable)

def is_debug_enabled() -> bool:
    return DEBUG_ENABLED


class _Handler(http.server.BaseHTTPRequestHandler):  # pragma: no cover
    def log_message(self, format, *args):
        return

    def _send(self, code: int, obj: Any):
        data = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (ConnectionAbortedError, BrokenPipeError, OSError) as e:  # pragma: no cover
            # 客户端在响应发送途中断开 (WinError 10053/10054 或 POSIX EPIPE/ECONNRESET)，忽略即可，不影响后续请求。
            # 选择静默处理 (方案A)，避免在频繁探测/超时重试场景刷屏。
            pass
    def do_GET(self):  # type: ignore
        if self.path == '/instances':
            with _lock:
                _debug_log('GET /instances', count=len(_instances))
                self._send(200, _instances)
        elif self.path == '/current_instance':
            with _lock:
                _debug_log('GET /current_instance', port=_current_instance_port)
                self._send(200, {"port": _current_instance_port})
        elif self.path == '/debug':
            self._send(200, {"enabled": DEBUG_ENABLED})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # type: ignore
        global _current_instance_port
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length) if length else b''
        try:
            payload = json.loads(raw.decode('utf-8') or '{}')
        except Exception:
            payload = {}
        _debug_log('POST', path=self.path, client=f"{self.client_address}", content_length=length)
        if self.path == '/register':
            needed = {'pid', 'port'}
            if not needed.issubset(payload):
                self._send(400, {"error": "missing fields"})
                return
            with _lock:
                pid = payload['pid']
                existing = [e for e in _instances if e.get('pid') != pid]
                _instances.clear()
                _instances.extend(existing)
                _instances.append(payload)
            _debug_log('REGISTER', pid=payload.get('pid'), port=payload.get('port'), input_file=payload.get('input_file'), idb=payload.get('idb'))
            self._send(200, {"status": "ok"})
        elif self.path == '/deregister':
            pid = payload.get('pid')
            if pid is None:
                self._send(400, {"error": "missing pid"})
                return
            with _lock:
                remaining = [e for e in _instances if e.get('pid') != pid]
                if _current_instance_port and not any(e.get('port') == _current_instance_port for e in remaining):
                    _current_instance_port = None
                _instances.clear()
                _instances.extend(remaining)
            _debug_log('DEREGISTER', pid=pid, remaining=len(_instances))
            self._send(200, {"status": "ok"})
        elif self.path == '/select_instance':
            port = payload.get('port')
            with _lock:
                if port is None:
                    # Auto-select if port is not provided
                    if not _instances:
                        self._send(404, {"error": "No instances to select from"})
                        return
                    
                    # Prioritize 10000, then earliest started
                    sorted_instances = sorted(_instances, key=lambda x: (x.get('port') != 10000, x.get('started', float('inf'))))
                    _current_instance_port = sorted_instances[0].get('port')
                else:
                    if not any(e.get('port') == port for e in _instances):
                        self._send(404, {"error": f"Instance with port {port} not found"})
                        return
                    _current_instance_port = port
            _debug_log('SELECT_INSTANCE', requested=port, selected=_current_instance_port)
            self._send(200, {"status": "ok", "selected_port": _current_instance_port})
        elif self.path == '/debug':
            # Toggle debug logging: payload { enable: bool }
            enable = bool(payload.get('enable') if 'enable' in payload else payload.get('enabled', False))
            set_debug(enable)
            self._send(200, {"status": "ok", "enabled": DEBUG_ENABLED})
        elif self.path == '/call':
            # payload: { pid | port, tool, params }
            target_pid = payload.get('pid')
            target_port = payload.get('port')
            tool = payload.get('tool')
            params = payload.get('params') or {}
            if not tool:
                self._send(400, {"error": "missing tool"})
                return
            with _lock:
                target = None
                if target_pid is not None:
                    for e in _instances:
                        if e.get('pid') == target_pid:
                            target = e
                            break
                elif target_port is not None:
                    for e in _instances:
                        if e.get('port') == target_port:
                            target = e
                            break
            if target is None:
                self._send(404, {"error": "instance not found"})
                return
            port = target.get('port')
            if not isinstance(port, int):
                self._send(500, {"error": "bad target port"})
                return
            # 从请求体读取可选超时（AI 可传入自定义超时）
            req_timeout = payload.get('timeout')
            try:
                effective_timeout = int(req_timeout) if req_timeout and int(req_timeout) > 0 else REQUEST_TIMEOUT
            except (ValueError, TypeError):
                effective_timeout = REQUEST_TIMEOUT
            t0 = time.time()
            _debug_log('CALL_BEGIN', tool=tool, target_port=port, pid=target.get('pid'), params_keys=list((params or {}).keys()), timeout=effective_timeout)
            # Forward the tool call over HTTP MCP (JSON-RPC) using fastmcp Client dynamically.
            # 内部通信固定使用 127.0.0.1（协调器与实例在同一台机器上）
            mcp_url = f"http://{LOCALHOST}:{port}/mcp/"
            
            # 先验证端口是否可连接
            try:
                with socket.create_connection((LOCALHOST, port), timeout=1.0):
                    pass  # 端口可连接
            except (ConnectionRefusedError, OSError, socket.timeout) as e:
                err_msg = f"Port {port} not reachable: {type(e).__name__}: {e}"
                _log_info(f"[PRE_CHECK_FAIL] {err_msg}")
                self._send(500, {"error": err_msg})
                return
            
            # 获取 per-port 锁，序列化对同一 IDA 实例的并发调用，
            # 防止同时创建多个 MCP session 导致 session manager 崩溃。
            with _call_locks_guard:
                if port not in _call_locks:
                    _call_locks[port] = threading.Lock()
                call_lock = _call_locks[port]
            
            acquired = call_lock.acquire(timeout=effective_timeout + 5)
            if not acquired:
                self._send(503, {"error": f"Timed out waiting for call lock on port {port}"})
                return
            
            try:
                from fastmcp import Client  # type: ignore
                import asyncio
                
                async def _do():
                    async with Client(mcp_url, timeout=effective_timeout) as c:  # type: ignore
                        resp = await c.call_tool(tool, params)
                        # Extract data from response content (JSON text)
                        # fastmcp returns data in resp.content[0].text as JSON string
                        data = None
                        if hasattr(resp, 'content') and resp.content:
                            for item in resp.content:
                                text = getattr(item, 'text', None)
                                if text:
                                    try:
                                        data = json.loads(text)
                                        break
                                    except (json.JSONDecodeError, TypeError):
                                        continue
                        # Fallback: try resp.data with normalization
                        if data is None and hasattr(resp, 'data') and resp.data is not None:
                            def norm(x):
                                if isinstance(x, list):
                                    return [norm(i) for i in x]
                                if isinstance(x, dict):
                                    return {k: norm(v) for k, v in x.items()}
                                if hasattr(x, 'model_dump'):
                                    return x.model_dump()
                                if hasattr(x, '__dict__') and x.__dict__:
                                    return norm(vars(x))
                                return x
                            data = norm(resp.data)
                        return {"tool": tool, "data": data}
                
                result = asyncio.run(_do())
                
                dt_ms = int((time.time() - t0) * 1000)
                # Attempt to estimate response size
                try:
                    resp_size = len(json.dumps(result, ensure_ascii=False))
                except Exception:
                    resp_size = 0
                _debug_log('CALL_OK', tool=tool, target_port=port, elapsed_ms=dt_ms, resp_size=resp_size)
                self._send(200, result)
            except Exception as e:  # pragma: no cover
                import traceback
                dt_ms = int((time.time() - t0) * 1000)
                err_detail = f"{type(e).__name__}: {e}"
                
                # 客户端断开连接时静默处理，不输出大量日志
                is_disconnect = any(x in err_detail for x in [
                    'BrokenResourceError', 'ConnectionAbortedError', 'ReadTimeout',
                    'ConnectionResetError', 'BrokenPipeError'
                ])
                
                if is_disconnect:
                    _debug_log('CLIENT_DISCONNECT', tool=tool, target_port=port, elapsed_ms=dt_ms)
                else:
                    tb = traceback.format_exc()
                    _debug_log('CALL_FAIL', tool=tool, target_port=port, elapsed_ms=dt_ms, error=err_detail, traceback=tb)
                    # 输出到 IDA 控制台便于诊断
                    _log_info(f"[CALL_FAIL] url={mcp_url} tool={tool}: {err_detail}")
                
                # 尝试发送错误响应，忽略连接已断开的情况
                try:
                    self._send(500, {"error": f"call failed ({mcp_url}): {err_detail}"})
                except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
                    pass  # 客户端已断开，忽略
            finally:
                call_lock.release()
        else:
            self._send(404, {"error": "not found"})

def _start_coordinator():  # pragma: no cover
    global _server_thread
    if _server_thread and _server_thread.is_alive():
        return
    def run():
        try:
            httpd = http.server.HTTPServer((COORD_HOST, COORD_PORT), _Handler)
            httpd.serve_forever()
        except Exception:
            pass
    _server_thread = threading.Thread(target=run, name="IDA-MCP-Registry", daemon=True)
    _server_thread.start()
    
    # 根据配置启动 HTTP 代理
    _try_start_http_proxy()


def _try_start_http_proxy():  # pragma: no cover
    """根据配置启动 HTTP MCP 代理。"""
    try:
        from .config import get_http_host, get_http_port, get_http_path, is_http_enabled
        
        # 检查是否启用 HTTP 模式
        if not is_http_enabled():
            return
        
        from .http import start_http_proxy, get_http_url
        
        host = get_http_host()
        port = get_http_port()
        path = get_http_path()
        
        if start_http_proxy(host, port, path):
            url = get_http_url()
            _log_info(f"HTTP MCP proxy started at {url}")
        else:
            _log_info("Failed to start HTTP MCP proxy")
    except Exception as e:
        # HTTP 模块不可用时静默忽略
        _log_info(f"HTTP proxy not started: {e}")


def _log_info(msg: str):  # pragma: no cover
    """输出日志到 IDA 消息窗口或控制台。"""
    ts = time.strftime('%H:%M:%S', time.localtime())
    line = f"[IDA-MCP][INFO][{ts}] {msg}\n"
    try:
        if hasattr(ida_kernwin, 'execute_sync') and hasattr(ida_kernwin, 'msg'):
            def _emit():
                try:
                    ida_kernwin.msg(line)
                except Exception:
                    print(line, end='')
                return 0
            try:
                ida_kernwin.execute_sync(_emit, ida_kernwin.MFF_READ)
            except Exception:
                try:
                    ida_kernwin.msg(line)
                except Exception:
                    print(line, end='')
        else:
            print(line, end='')
    except Exception:
        pass

def _coordinator_alive() -> bool:
    """检测协调器是否存活（内部通信，固定使用 127.0.0.1）。"""
    try:
        with socket.create_connection((LOCALHOST, COORD_PORT), timeout=0.3):
            return True
    except OSError:
        return False


def init_and_register(port: int, input_file: str | None, idb_path: str | None):
    """确保协调器运行, 若不存在则当前进程抢占成为协调器, 然后注册本实例。

    参数:
        port: 当前实例监听的 MCP 端口
        input_file: 输入文件路径 (可能为 None)
        idb_path: IDB 路径 (可能为 None)
    逻辑:
        1. 检查是否有传输方式启用，至少需要 enable_stdio 或 enable_http 其一
        2. 尝试连接 11337; 若失败则尝试 bind -> 成为协调器并启动 HTTP 服务
        3. 构造实例 payload 并 POST /register
        4. 注册 atexit 钩子, 确保正常退出时自动注销
    """
    from .config import is_stdio_enabled, is_http_enabled
    
    # 如果两种传输方式都禁用，则不启动协调器
    if not is_stdio_enabled() and not is_http_enabled():
        _log_info("Both stdio and HTTP modes are disabled, coordinator not started")
        return
    
    global _is_coordinator
    if not _coordinator_alive():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((COORD_HOST, COORD_PORT))
            s.close()
            _is_coordinator = True
            _start_coordinator()
        except OSError:
            _is_coordinator = False
    payload = {
        'pid': _self_pid,
        'port': port,
        'host': IDA_HOST,  # 实例监听地址，用于远程访问
        'input_file': input_file,
        'idb': idb_path,
        'started': time.time(),
        'python': sys.version.split()[0],
    }
    # 如果是协调器，直接操作内存；否则通过 HTTP 注册
    if _is_coordinator:
        _register_local(payload)
    else:
        _post_json('/register', payload)
    atexit.register(deregister)

def is_coordinator() -> bool:
    """返回当前进程是否为协调器 (第一个绑定 11337 的实例).

    供外部在完成 init_and_register 调用后输出额外日志。
    """
    return _is_coordinator

def _post_json(path: str, obj: Any):
    """通过 HTTP POST 发送 JSON 到协调器（内部通信，固定使用 127.0.0.1）。"""
    data = json.dumps(obj).encode('utf-8')
    req = urllib.request.Request(f'http://{LOCALHOST}:{COORD_PORT}{path}', data=data, method='POST', headers={'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT)
    except Exception:
        pass

def _register_local(payload: dict):
    """本地注册实例（协调器进程直接操作内存）。"""
    with _lock:
        pid = payload.get('pid')
        existing = [e for e in _instances if e.get('pid') != pid]
        _instances.clear()
        _instances.extend(existing)
        _instances.append(payload)
    _debug_log('REGISTER_LOCAL', pid=payload.get('pid'), port=payload.get('port'))

def get_instances() -> List[Dict[str, Any]]:
    """获取所有已注册实例（内部通信，固定使用 127.0.0.1）。"""
    if _is_coordinator:
        with _lock:
            return list(_instances)
    try:
        with urllib.request.urlopen(f'http://{LOCALHOST}:{COORD_PORT}/instances', timeout=REQUEST_TIMEOUT) as resp:  # type: ignore
            raw = resp.read()
            data = json.loads(raw.decode('utf-8') or '[]')
            if isinstance(data, list):
                return data
    except Exception:
        return []
    return []

def deregister():  # pragma: no cover
    _post_json('/deregister', {'pid': _self_pid})

def call_tool(pid: int | None = None, port: int | None = None, tool: str = '', params: dict | None = None) -> dict:
    """调用指定实例的工具（内部通信，固定使用 127.0.0.1）。"""
    body = json.dumps({"pid": pid, "port": port, "tool": tool, "params": params or {}}).encode('utf-8')
    req = urllib.request.Request(f'http://{LOCALHOST}:{COORD_PORT}/call', data=body, method='POST', headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # type: ignore
            raw = resp.read()
            return json.loads(raw.decode('utf-8') or '{}')
    except Exception as e:
        return {"error": str(e)}

def check_connection() -> dict:
    """检查当前是否存在至少一个已注册的 IDA MCP 实例。

    返回:
        {"ok": True, "count": n}  当 n>0 时
        {"ok": False, "count": 0} 当没有实例或协调器不可达
    说明:
        * 供外部快速健康探测使用, 不会抛异常, 统一结构。
    """
    inst = get_instances()
    return {"ok": bool(inst), "count": len(inst)}
