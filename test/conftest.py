"""pytest 配置和共享 fixtures。

测试框架设计：
1. coordinator_available - 检查 gateway 内部 API 是否运行
2. instance_port - 获取可用 IDA 实例端口
3. tool_caller - 工具调用函数（支持 stdio 和 http 两种模式）
4. 前置信息 fixtures（session 级别缓存）:
   - first_function - 获取第一个函数信息
   - first_string - 获取第一个字符串信息
   - first_global - 获取第一个全局变量信息
   - metadata - 获取 IDB 元数据
5. API 调用日志 - 保存到 .artifacts/api_logs/ 目录
   - stdio 模式: stdio_*.json
   - http 模式: http_*.json

运行方式：
    pytest                          # 运行所有测试（两种模式）
    pytest --transport=stdio        # 只运行 stdio 模式
    pytest --transport=http         # 只运行 http 模式
"""
import pytest
import urllib.request
import urllib.error
import json
import os
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Dict, List, Union


# ============================================================================
# 命令行参数
# ============================================================================

def pytest_addoption(parser):
    """添加命令行选项。"""
    parser.addoption(
        "--transport",
        action="store",
        default="both",
        choices=["stdio", "http", "both"],
        help="Transport mode to test: stdio, http, or both (default: both)"
    )


# ============================================================================
# 配置
# ============================================================================

# Gateway 内部 API 地址
COORDINATOR_HOST = "127.0.0.1"
COORDINATOR_PORT = 11338
COORDINATOR_BASE_PATH = "/internal"

# HTTP 代理地址
HTTP_PROXY_HOST = "127.0.0.1"
HTTP_PROXY_PORT = 11338
HTTP_PROXY_PATH = "/mcp"


# ============================================================================
# API 调用日志
# ============================================================================

# 按传输模式分开的日志
_api_call_logs: Dict[str, List[Dict[str, Any]]] = {
    "stdio": [],
    "http": [],
}

# 日志目录路径
_LOG_DIR = str(Path(__file__).resolve().parent.parent / ".artifacts" / "api_logs")

# API 分类映射（与 IDA API 工具名一致）
_API_CATEGORIES = {
    # Core
    "check_connection": "core",
    "list_instances": "core",
    "get_metadata": "core",
    "list_functions": "core",
    "get_function": "core",
    "list_globals": "core",
    "list_strings": "core",
    "list_local_types": "core",
    "get_entry_points": "core",
    "convert_number": "core",
    "list_imports": "core",
    "list_exports": "core",
    "list_segments": "core",
    "get_cursor": "core",
    "close_ida": "lifecycle",
    "open_in_ida": "lifecycle",
    
    # MemoryAnalysis
    "decompile": "analysis",
    "disasm": "analysis",
    "linear_disasm": "analysis",
    "get_callers": "analysis",
    "get_callees": "analysis",
    "get_function_signature": "analysis",
    "get_pseudocode_lines": "analysis",
    "xrefs_to": "analysis",
    "xrefs_from": "analysis",
    "xrefs_to_field": "analysis",
    "find_bytes": "analysis",
    "get_basic_blocks": "analysis",
    
    # Memory
    "get_bytes": "memory",
    "read_scalar": "memory",
    "get_string": "memory",
    
    # Modify
    "set_comment": "modify",
    "rename_function": "modify",
    "rename_local_variable": "modify",
    "rename_global_variable": "modify",
    "patch_bytes": "modify",
    "create_function": "modeling",
    "delete_function": "modeling",
    "make_code": "modeling",
    "undefine_items": "modeling",
    "make_data": "modeling",
    "make_string": "modeling",
    
    # Types
    "declare_struct": "types",
    "declare_enum": "types",
    "declare_typedef": "types",
    "set_function_prototype": "types",
    "set_local_variable_type": "types",
    "set_global_variable_type": "types",
    "list_structs": "types",
    "get_struct_info": "types",
    
    # Stack
    "stack_frame": "stack",
    "declare_stack": "stack",
    "delete_stack": "stack",
    
    # Debug
    "dbg_start": "debug",
    "dbg_exit": "debug",
    "dbg_continue": "debug",
    "dbg_step_into": "debug",
    "dbg_step_over": "debug",
    "dbg_run_to": "debug",
    "dbg_regs": "debug",
    "dbg_callstack": "debug",
    "dbg_list_bps": "debug",
    "dbg_add_bp": "debug",
    "dbg_delete_bp": "debug",
    "dbg_enable_bp": "debug",
    "dbg_read_mem": "debug",
    "dbg_write_mem": "debug",
}

# 这些工具只在 proxy 暴露，不应通过 gateway /call 转发到某个现有实例。
_PROXY_ONLY_TOOLS = {
    "open_in_ida",
}


def _call_proxy_only_tool_locally(tool_name: str, params: dict) -> Any:
    """Execute proxy-only lifecycle tools locally for stdio-mode test coverage."""
    if tool_name == "open_in_ida":
        from ida_mcp.proxy import lifecycle

        return lifecycle.open_in_ida(
            params.get("file_path", ""),
            extra_args=params.get("extra_args"),
        )

    return {"error": f"Unsupported proxy-only tool: {tool_name}"}


def _is_proxy_transport_error(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    error = result.get("error")
    if isinstance(error, dict):
        error = error.get("message", "")
    if not isinstance(error, str):
        return False
    return (
        "500 Internal Server Error" in error
        or "Unexpected content type" in error
        or "HTTP proxy not available" in error
    )


def _get_api_category(tool_name: str) -> str:
    """获取 API 分类。"""
    return _API_CATEGORIES.get(tool_name, "other")


def _log_api_call(transport: str, tool_name: str, params: dict, port: Optional[int], result: Any, duration_ms: float) -> None:
    """记录 API 调用。"""
    _api_call_logs[transport].append({
        "timestamp": datetime.now().isoformat(),
        "transport": transport,
        "category": _get_api_category(tool_name),
        "tool": tool_name,
        "params": params,
        "port": port,
        "result": result,
        "duration_ms": round(duration_ms, 2),
    })


def _save_api_log() -> None:
    """保存 API 日志到多个文件（按传输模式和分类）。"""
    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
    except Exception:
        return
    
    all_files = []
    total_calls = 0
    stats_by_transport: Dict[str, Dict[str, int]] = {}
    
    for transport, calls in _api_call_logs.items():
        if not calls:
            continue
        
        total_calls += len(calls)
        stats_by_transport[transport] = {}
    
        # 按分类组织
        categorized: Dict[str, List[Dict[str, Any]]] = {}
        for call in calls:
            category = call.get("category", "other")
            if category not in categorized:
                categorized[category] = []
            categorized[category].append(call)
    
        # 保存各分类文件
        for category, cat_calls in categorized.items():
            # 文件名格式: {transport}_{category}.json
            filename = f"{transport}_{category}.json"
            log_file = os.path.join(_LOG_DIR, filename)
            
            try:
                with open(log_file, "w", encoding="utf-8") as f:
                    json.dump({
                        "transport": transport,
                        "category": category,
                        "generated_at": datetime.now().isoformat(),
                        "total_calls": len(cat_calls),
                        "calls": cat_calls,
                    }, f, indent=2, ensure_ascii=False, default=str)
                
                all_files.append(filename)
                stats_by_transport[transport][category] = len(cat_calls)
            except Exception:
                pass
        
        # 保存汇总文件
    try:
        # 检查是否存在 uri.json（由 test_resources.py 生成）
        for prefix in ["stdio_", "http_", ""]:
            uri_file = os.path.join(_LOG_DIR, f"{prefix}uri.json")
            if os.path.exists(uri_file):
                all_files.append(f"{prefix}uri.json")
        
        summary_file = os.path.join(_LOG_DIR, "_summary.json")
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.now().isoformat(),
                "total_calls": total_calls,
                "stats_by_transport": stats_by_transport,
                "files": sorted(set(all_files)),
            }, f, indent=2, ensure_ascii=False, default=str)
        
        if total_calls > 0:
            print(f"\n[API Log] Saved {total_calls} calls to {_LOG_DIR}/")
            for transport, stats in stats_by_transport.items():
                if stats:
                    files_info = ', '.join(f'{cat} ({cnt})' for cat, cnt in sorted(stats.items()))
                    print(f"[API Log] {transport}: {files_info}")
    except Exception as e:
        print(f"\n[API Log] Failed to save summary: {e}")


# ============================================================================
# 地址解析辅助函数
# ============================================================================

def parse_addr(addr: Union[str, int]) -> int:
    """将地址转换为整数（支持 hex string 或 int）。"""
    if isinstance(addr, str):
        return int(addr, 16)
    return addr


# ============================================================================
# HTTP 工具函数 (stdio 模式 - 通过 gateway internal API)
# ============================================================================

def http_get(url: str, timeout: float = 5.0) -> Any:
    """发送 GET 请求。"""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}


def http_post(url: str, data: dict, timeout: float = 10.0) -> Any:
    """发送 POST 请求。"""
    try:
        body = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}


def call_tool_stdio(tool_name: str, params: dict, port: Optional[int] = None) -> Any:
    """通过 gateway internal API 调用 IDA 工具。

    注意：测试里的“stdio”路径验证 gateway 转发语义，不会单独拉起 stdio proxy 进程。
    """
    if tool_name in _PROXY_ONLY_TOOLS:
        # lifecycle 的 open_in_ida 是 proxy-side tool；测试中的“stdio”路径不单独
        # 启动 stdio proxy 进程，因此优先复用 HTTP proxy。若当前环境残留了一个
        # 返回通用 500 的旧/坏 gateway，则退回到本地 proxy-side API，仅验证语义。
        if _is_http_proxy_available():
            data = call_tool_http(tool_name, params, None)
            if not _is_proxy_transport_error(data):
                return data
        else:
            data = {"error": f"HTTP proxy not available for proxy-only tool: {tool_name}"}

        import time

        start_time = time.perf_counter()
        local_data = _call_proxy_only_tool_locally(tool_name, params)
        duration_ms = (time.perf_counter() - start_time) * 1000
        _log_api_call("stdio", tool_name, params, port, local_data, duration_ms)
        return local_data

    import time
    start_time = time.perf_counter()
    
    url = f"http://{COORDINATOR_HOST}:{COORDINATOR_PORT}{COORDINATOR_BASE_PATH}/call"
    payload = {
        "tool": tool_name,
        "params": params,
    }
    if port:
        payload["port"] = port
    result = http_post(url, payload)
    
    duration_ms = (time.perf_counter() - start_time) * 1000
    
    # 协调器返回 {"tool": ..., "data": ...} 格式，提取 data 字段
    data = result
    if isinstance(result, dict) and "data" in result:
        data = result["data"]
    
    # 记录 API 调用
    _log_api_call("stdio", tool_name, params, port, data, duration_ms)
    
    return data


# ============================================================================
# HTTP 工具函数 (http 模式 - 通过 HTTP 代理)
# ============================================================================

def call_tool_http(tool_name: str, params: dict, port: Optional[int] = None) -> Any:
    """通过 HTTP 代理调用 IDA 工具 (http 模式)。"""
    import time
    start_time = time.perf_counter()
    
    try:
        from fastmcp import Client
        
        async def _call():
            url = f"http://{HTTP_PROXY_HOST}:{HTTP_PROXY_PORT}{HTTP_PROXY_PATH}"
            async with Client(url, timeout=30) as client:
                call_params = dict(params)
                if port and tool_name not in _PROXY_ONLY_TOOLS:
                    call_params.setdefault("port", port)

                resp = await client.call_tool(tool_name, call_params)
                
                # 提取返回数据
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
                
                if data is None and hasattr(resp, 'data') and resp.data is not None:
                    data = resp.data
                
                return data

        data = None
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                data = asyncio.run(_call())
                last_error = None
                break
            except Exception as e:
                last_error = e
                if "Session terminated" not in str(e) or attempt == 1:
                    raise
                time.sleep(0.2)
        if last_error is not None and data is None:
            raise last_error
        
    except Exception as e:
        data = {"error": str(e)}
    
    duration_ms = (time.perf_counter() - start_time) * 1000
    
    # 记录 API 调用
    _log_api_call("http", tool_name, params, port, data, duration_ms)
    
    return data


# ============================================================================
# 传输模式检测
# ============================================================================

def _is_http_proxy_available() -> bool:
    """检查 HTTP 代理是否可用。"""
    try:
        url = f"http://{HTTP_PROXY_HOST}:{HTTP_PROXY_PORT}{HTTP_PROXY_PATH}"
        # 尝试连接
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((HTTP_PROXY_HOST, HTTP_PROXY_PORT))
        sock.close()
        return result == 0
    except Exception:
        return False


def _is_coordinator_available() -> bool:
    """检查 gateway internal API 是否可用。"""
    url = f"http://{COORDINATOR_HOST}:{COORDINATOR_PORT}{COORDINATOR_BASE_PATH}/healthz"
    result = http_get(url)
    return bool(isinstance(result, dict) and result.get("ok"))


# ============================================================================
# Fixtures
# ============================================================================

def pytest_generate_tests(metafunc):
    """根据命令行参数生成测试参数。"""
    if "transport_mode" in metafunc.fixturenames:
        transport = metafunc.config.getoption("--transport")
        if transport == "both":
            modes = ["stdio", "http"]
        else:
            modes = [transport]
        metafunc.parametrize("transport_mode", modes, scope="session")


@pytest.fixture(scope="session")
def transport_mode(request):
    """获取当前测试的传输模式。"""
    # 默认值，如果没有参数化
    return getattr(request, "param", "stdio")


@pytest.fixture(scope="session")
def coordinator_available():
    """检查 gateway internal API 是否可用。"""
    if not _is_coordinator_available():
        pytest.skip("Gateway internal API not available at 127.0.0.1:11338/internal")
    return True


@pytest.fixture(scope="session")
def http_proxy_available():
    """检查 HTTP 代理是否可用。"""
    if not _is_http_proxy_available():
        pytest.skip(f"HTTP proxy not available at {HTTP_PROXY_HOST}:{HTTP_PROXY_PORT}")
    return True


@pytest.fixture(scope="session")
def instance_port(coordinator_available):
    """获取第一个可用实例的端口。"""
    url = f"http://{COORDINATOR_HOST}:{COORDINATOR_PORT}{COORDINATOR_BASE_PATH}/instances"
    result = http_get(url)
    # API 直接返回列表，不是 {"instances": [...]} 格式
    instances = result if isinstance(result, list) else []
    if not instances:
        pytest.skip("No IDA instances available")
    return instances[0].get("port")


@pytest.fixture
def tool_caller(request, instance_port):
    """返回工具调用函数（根据传输模式选择）。"""
    # 获取传输模式
    transport = getattr(request, "param", None)
    if transport is None:
        # 尝试从命令行获取
        transport = request.config.getoption("--transport", "stdio")
        if transport == "both":
            transport = "stdio"  # 默认使用 stdio
    
    if transport == "http":
        # 检查 HTTP 代理可用性
        if not _is_http_proxy_available():
            pytest.skip("HTTP proxy not available")
        
        def caller(tool_name: str, params: Optional[dict] = None) -> Any:
            return call_tool_http(tool_name, params or {}, instance_port)
    else:
        def caller(tool_name: str, params: Optional[dict] = None) -> Any:
            return call_tool_stdio(tool_name, params or {}, instance_port)
    
    return caller


# ============================================================================
# 前置信息 Fixtures（Session 级别缓存）
# ============================================================================

@pytest.fixture(scope="session")
def metadata(instance_port) -> Dict[str, Any]:
    """获取 IDB 元数据（缓存）。"""
    result = call_tool_stdio("get_metadata", {}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot get metadata: {result['error']}")
    return result


@pytest.fixture(scope="session")
def functions_cache(instance_port) -> List[Dict[str, Any]]:
    """获取函数列表缓存（前 100 个）。"""
    # 显式传递所有参数以兼容签名问题
    result = call_tool_stdio("list_functions", {"offset": 0, "count": 100}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot list functions: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def strings_cache(instance_port) -> List[Dict[str, Any]]:
    """获取字符串列表缓存（前 100 个）。"""
    # 显式传递所有参数以兼容签名问题
    result = call_tool_stdio("list_strings", {"offset": 0, "count": 100}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot list strings: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def globals_cache(instance_port) -> List[Dict[str, Any]]:
    """获取全局变量列表缓存（前 100 个）。"""
    # 工具名为 "list_globals"（与 IDA API 一致）
    result = call_tool_stdio("list_globals", {"offset": 0, "count": 100}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot list globals: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def entry_points_cache(instance_port) -> List[Dict[str, Any]]:
    """获取入口点缓存。"""
    result = call_tool_stdio("get_entry_points", {}, instance_port)
    if "error" in result:
        return []  # 入口点可能为空，不跳过测试
    return result.get("items", [])


@pytest.fixture(scope="session")
def local_types_cache(instance_port) -> List[Dict[str, Any]]:
    """获取本地类型缓存。"""
    result = call_tool_stdio("list_local_types", {}, instance_port)
    if "error" in result:
        return []  # 类型可能为空，不跳过测试
    return result.get("items", [])


# ============================================================================
# 便捷的单项 Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def first_function(functions_cache) -> Dict[str, Any]:
    """获取第一个函数（用于需要函数地址的测试）。"""
    if not functions_cache:
        pytest.skip("No functions available in IDB")
    return functions_cache[0]


@pytest.fixture(scope="session")
def first_function_address(first_function) -> int:
    """获取第一个函数的起始地址。"""
    addr = first_function["start_ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def first_function_name(first_function) -> str:
    """获取第一个函数的名称。"""
    return first_function["name"]


@pytest.fixture(scope="session")
def first_string(strings_cache) -> Dict[str, Any]:
    """获取第一个字符串。"""
    if not strings_cache:
        pytest.skip("No strings available in IDB")
    return strings_cache[0]


@pytest.fixture(scope="session")
def first_string_address(first_string) -> int:
    """获取第一个字符串的地址。"""
    addr = first_string["ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def first_global(globals_cache) -> Dict[str, Any]:
    """获取第一个全局变量。"""
    if not globals_cache:
        pytest.skip("No globals available in IDB")
    return globals_cache[0]


@pytest.fixture(scope="session")
def first_global_address(first_global) -> int:
    """获取第一个全局变量的地址。"""
    addr = first_global["ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def main_function(functions_cache) -> Optional[Dict[str, Any]]:
    """尝试获取 main 函数。"""
    for func in functions_cache:
        if func.get("name") in ("main", "_main", "WinMain", "wWinMain", "mainCRTStartup"):
            return func
    return None


@pytest.fixture(scope="session")
def main_function_address(main_function) -> int:
    """获取 main 函数地址。"""
    if not main_function:
        pytest.skip("No main function found")
    addr = main_function["start_ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


# ============================================================================
# 测试标记和钩子
# ============================================================================

def pytest_configure(config):
    """注册自定义标记。"""
    config.addinivalue_line("markers", "debug: 需要调试器的测试")
    config.addinivalue_line("markers", "analysis: 分析工具测试")
    config.addinivalue_line("markers", "core: 核心工具测试")
    config.addinivalue_line("markers", "memory: 内存工具测试")
    config.addinivalue_line("markers", "modify: 修改工具测试")
    config.addinivalue_line("markers", "types: 类型工具测试")
    config.addinivalue_line("markers", "stack: 栈帧工具测试")
    config.addinivalue_line("markers", "resources: URI 资源测试")


def pytest_sessionfinish(session, exitstatus):
    """测试结束时保存 API 日志。"""
    _save_api_log()
