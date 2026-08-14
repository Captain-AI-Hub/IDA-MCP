"""pytest 配置和共享 fixtures。

测试框架设计：
1. gateway_internal_available - 检查 gateway 内部 API 是否运行
2. instance_port - 获取可用 IDA 实例端口
3. tool_caller - 通过 gateway proxy 调用工具
4. 前置信息 fixtures（session 级别缓存）:
   - first_function - 获取第一个函数信息
   - first_string - 获取第一个字符串信息
   - first_global - 获取第一个全局变量信息
   - metadata - 获取 IDB 元数据
5. API 调用日志 - 保存到 .artifacts/api_logs/ 目录，文件名为 http_*.json

运行方式：
    pytest
"""

import sys
import os

# 确保 ida_mcp 包可导入 — 测试位于仓库根目录的 test/
_pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

import pytest
import urllib.request
import json
import os
import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Dict, List, Union


# ============================================================================
# 命令行参数
# ============================================================================


def pytest_addoption(parser):
    """添加命令行选项。"""
    parser.addoption(
        "--allow-destructive-lifecycle",
        action="store_true",
        default=False,
        help="Allow lifecycle tests that close a live IDA instance.",
    )


# ============================================================================
# 配置
# ============================================================================

# Gateway 内部 API 地址
GATEWAY_INTERNAL_HOST = "127.0.0.1"
GATEWAY_INTERNAL_PORT = 11338
GATEWAY_INTERNAL_BASE_PATH = "/internal"

# Gateway MCP proxy 地址
GATEWAY_PROXY_HOST = "127.0.0.1"
GATEWAY_PROXY_PORT = 11338
GATEWAY_PROXY_PATH = "/mcp"


# ============================================================================
# API 调用日志
# ============================================================================

# API 调用日志
_api_call_logs: List[Dict[str, Any]] = []

# 日志目录路径
_LOG_DIR = str(Path(__file__).resolve().parent.parent / ".artifacts" / "api_logs")
_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

# API 分类映射（与 IDA API 工具名一致）
_API_CATEGORIES = {
    # Core
    "check_connection": "core",
    "list_instances": "core",
    "get_metadata": "core",
    "list_functions": "core",
    "list_globals": "core",
    "list_strings": "core",
    "list_local_types": "core",
    "get_entry_points": "core",
    "convert_number": "core",
    "list_imports": "core",
    "list_exports": "core",
    "list_segments": "core",
    "get_cursor": "core",
    "survey_binary": "core",
    "close_ida": "lifecycle",
    "open_in_ida": "lifecycle",
    "save_idb": "lifecycle",
    # MemoryAnalysis
    "decompile": "analysis",
    "disasm": "analysis",
    "linear_disasm": "analysis",
    "get_callers": "analysis",
    "get_callees": "analysis",
    "get_function_signature": "analysis",
    "xrefs_to": "analysis",
    "xrefs_from": "analysis",
    "xrefs_to_field": "analysis",
    "find_bytes": "analysis",
    "get_basic_blocks": "analysis",
    "find_regex": "analysis",
    "search_text": "analysis",
    "find_instructions": "analysis",
    "callgraph": "analysis",
    "trace_data_flow": "analysis",
    "make_signature": "analysis",
    "make_signature_for_function": "analysis",
    "make_signature_for_range": "analysis",
    "find_xref_signatures": "analysis",
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
    "apply_patch": "modify",
    "add_bookmark": "modify",
    "patch_asm": "modify",
    "set_op_type": "modify",
    "force_recompile": "modify",
    "diff_before_after": "modify",
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
    "infer_types": "types",
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
    "dbg_status": "debug",
    "dbg_thread_regs": "debug",
}

# 这些工具只在 proxy 暴露，不应通过 gateway /call 转发到某个现有实例。
_PROXY_ONLY_TOOLS = {
    "open_in_ida",
    "close_ida",
}

# 这些工具不接受 port/timeout 参数（gateway-side 工具，无需指定目标实例）。
_NO_PORT_INJECTION_TOOLS = {
    "check_connection",
    "list_instances",
} | _PROXY_ONLY_TOOLS


def _get_api_category(tool_name: str) -> str:
    """获取 API 分类。"""
    return _API_CATEGORIES.get(tool_name, "other")


def _log_api_call(
    tool_name: str,
    params: dict,
    port: Optional[int],
    result: Any,
    duration_ms: float,
) -> None:
    """记录 API 调用。"""
    _api_call_logs.append(
        {
            "timestamp": datetime.now().isoformat(),
            "endpoint": "gateway",
            "category": _get_api_category(tool_name),
            "tool": tool_name,
            "params": params,
            "port": port,
            "result": result,
            "duration_ms": round(duration_ms, 2),
        }
    )


def _save_api_log() -> None:
    """保存 API 日志到多个文件（按传输模式和分类）。"""
    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
    except Exception:
        return

    all_files = []
    total_calls = len(_api_call_logs)
    stats_by_category: Dict[str, int] = {}

    # 按分类组织
    categorized: Dict[str, List[Dict[str, Any]]] = {}
    for call in _api_call_logs:
        category = call.get("category", "other")
        if category not in categorized:
            categorized[category] = []
        categorized[category].append(call)

    # 保存各分类文件
    for category, cat_calls in categorized.items():
        filename = f"{category}.json"
        log_file = os.path.join(_LOG_DIR, filename)

        try:
            with open(log_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "endpoint": "gateway",
                        "category": category,
                        "generated_at": datetime.now().isoformat(),
                        "total_calls": len(cat_calls),
                        "calls": cat_calls,
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )

            all_files.append(filename)
            stats_by_category[category] = len(cat_calls)
        except Exception:
            pass

        # 保存汇总文件
    try:
        # 检查是否存在 uri.json（由 test_resources.py 生成）
        uri_file = os.path.join(_LOG_DIR, "uri.json")
        if os.path.exists(uri_file):
            all_files.append("uri.json")

        summary_file = os.path.join(_LOG_DIR, "_summary.json")
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "generated_at": datetime.now().isoformat(),
                    "total_calls": total_calls,
                    "stats_by_category": stats_by_category,
                    "files": sorted(set(all_files)),
                },
                f,
                indent=2,
                ensure_ascii=False,
                default=str,
            )

        if total_calls > 0:
            print(f"\n[API Log] Saved {total_calls} calls to {_LOG_DIR}/")
            files_info = ", ".join(
                f"{cat} ({cnt})" for cat, cnt in sorted(stats_by_category.items())
            )
            print(f"[API Log] gateway: {files_info}")
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
# HTTP 工具函数
# ============================================================================


def http_get(url: str, timeout: float = 5.0) -> Any:
    """发送 GET 请求。"""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}


def call_tool_gateway(tool_name: str, params: dict, port: Optional[int] = None) -> Any:
    """通过 gateway proxy 调用 IDA 工具。"""
    import time

    start_time = time.perf_counter()

    try:
        from fastmcp import Client

        async def _call():
            url = f"http://{GATEWAY_PROXY_HOST}:{GATEWAY_PROXY_PORT}{GATEWAY_PROXY_PATH}"
            async with Client(url, timeout=30) as client:
                call_params = dict(params)
                if port and tool_name not in _NO_PORT_INJECTION_TOOLS:
                    call_params.setdefault("port", port)

                resp = await client.call_tool(tool_name, call_params)

                # 提取返回数据
                data = None
                raw_text = None
                if hasattr(resp, "content") and resp.content:
                    for item in resp.content:
                        text = getattr(item, "text", None)
                        if text:
                            try:
                                data = json.loads(text)
                                break
                            except (json.JSONDecodeError, TypeError):
                                if raw_text is None:
                                    raw_text = text
                                continue

                if data is None and hasattr(resp, "data") and resp.data is not None:
                    data = resp.data
                if data is None:
                    # 纯文本工具结果（如 decompile 伪代码）
                    data = raw_text

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
    _log_api_call(tool_name, params, port, data, duration_ms)

    return data


# ============================================================================
# Gateway 检测
# ============================================================================


def _is_gateway_proxy_available() -> bool:
    """检查 gateway proxy 是否可用。"""
    try:
        url = f"http://{GATEWAY_PROXY_HOST}:{GATEWAY_PROXY_PORT}{GATEWAY_PROXY_PATH}"
        # 尝试连接
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((GATEWAY_PROXY_HOST, GATEWAY_PROXY_PORT))
        sock.close()
        return result == 0
    except Exception:
        return False


def _is_gateway_internal_available() -> bool:
    """检查 gateway internal API 是否可用。"""
    url = f"http://{GATEWAY_INTERNAL_HOST}:{GATEWAY_INTERNAL_PORT}{GATEWAY_INTERNAL_BASE_PATH}/healthz"
    result = http_get(url)
    return bool(isinstance(result, dict) and result.get("ok"))


def _instance_health_rank(instance: dict) -> tuple[int, int, int]:
    """Rank registered instances for test routing.

    Tests should avoid stale, starting, quarantined, or unhealthy entries.
    When multiple healthy instances exist, prefer the historical default
    port 10000 and then the lowest numeric port for deterministic logs.
    """
    port = instance.get("port")
    effective_state = str(instance.get("effective_state") or "ready")
    health = str(instance.get("health") or "healthy")
    quarantined_until = float(instance.get("quarantined_until") or 0.0)
    is_ready = effective_state == "ready"
    is_healthy = health in {"healthy", "degraded"}
    is_quarantined = quarantined_until > time.time()
    return (
        0 if is_ready and is_healthy and not is_quarantined else 1,
        0 if port == 10000 else 1,
        int(port) if isinstance(port, int) else 65536,
    )


def _select_test_instance_port(instances: list[dict]) -> Optional[int]:
    complex_candidates = [
        instance
        for instance in instances
        if _instance_matches_sample(instance, "complex.exe")
    ]
    if complex_candidates:
        instances = complex_candidates

    candidates = [
        instance
        for instance in instances
        if isinstance(instance.get("port"), int)
        and str(instance.get("effective_state") or "ready") == "ready"
        and str(instance.get("health") or "healthy")
        not in {"unreachable", "unresponsive", "error"}
        and float(instance.get("quarantined_until") or 0.0) <= time.time()
    ]
    if not candidates:
        return None
    return int(sorted(candidates, key=_instance_health_rank)[0]["port"])


def _instance_matches_sample(instance: dict, sample_name: str) -> bool:
    expected = sample_name.lower()
    expected_stem = expected.rsplit(".", 1)[0]
    for key in ("input_file", "idb_path", "database_path", "path"):
        value = instance.get(key)
        if not value:
            continue
        name = os.path.basename(str(value)).lower()
        if name == expected or name.startswith(expected + ".") or name.startswith(expected_stem + "."):
            return True
    return False


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def gateway_internal_available():
    """检查 gateway internal API 是否可用。"""
    if not _is_gateway_internal_available():
        pytest.skip("Gateway internal API not available at 127.0.0.1:11338/internal")
    return True


@pytest.fixture(scope="session")
def gateway_proxy_available():
    """检查 gateway proxy 是否可用。"""
    if not _is_gateway_proxy_available():
        pytest.skip(f"Gateway proxy not available at {GATEWAY_PROXY_HOST}:{GATEWAY_PROXY_PORT}")
    return True


@pytest.fixture(scope="session")
def instance_port(gateway_internal_available):
    """获取可用于主测试的 complex.exe healthy/ready IDA 实例端口。"""
    url = f"http://{GATEWAY_INTERNAL_HOST}:{GATEWAY_INTERNAL_PORT}{GATEWAY_INTERNAL_BASE_PATH}/instances"
    result = http_get(url)
    # API 直接返回列表，不是 {"instances": [...]} 格式
    instances = result if isinstance(result, list) else []
    if not instances:
        pytest.skip("No IDA instances available")
    selected = _select_test_instance_port(instances)
    if selected is None:
        states = [
            {
                "port": item.get("port"),
                "health": item.get("health"),
                "effective_state": item.get("effective_state"),
                "quarantined_until": item.get("quarantined_until"),
            }
            for item in instances
        ]
        pytest.skip(f"No ready/healthy complex.exe IDA instance available: {states}")
    return selected


@pytest.fixture(scope="session")
def complex_baseline() -> Dict[str, Any]:
    """Loaded baseline harvested from test/samples/complex.exe."""
    baseline_path = _FIXTURE_DIR / "complex_baseline.json"
    with open(baseline_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _baseline_named_item(
    items: List[Dict[str, Any]],
    key: str,
    expected_name: str,
) -> Dict[str, Any]:
    for item in items:
        if item.get(key) == expected_name:
            return item
    pytest.skip(f"Baseline item not found: {expected_name}")


@pytest.fixture(scope="session")
def baseline_function(complex_baseline, functions_cache):
    def _get(name: str) -> Dict[str, Any]:
        expected = complex_baseline["functions"][name]
        item = _baseline_named_item(functions_cache, "name", name)
        assert str(item["start_ea"]).lower() == expected["start_ea"].lower()
        return item

    return _get


@pytest.fixture(scope="session")
def baseline_global(complex_baseline, globals_cache):
    def _get(name: str) -> Dict[str, Any]:
        expected = complex_baseline["globals"][name]
        item = _baseline_named_item(globals_cache, "name", name)
        assert str(item["ea"]).lower() == expected["ea"].lower()
        return item

    return _get


@pytest.fixture(scope="session")
def baseline_string(complex_baseline, strings_cache):
    def _get(text: str) -> Dict[str, Any]:
        item = _baseline_named_item(strings_cache, "text", text)
        expected = complex_baseline["strings"][text]
        item_ea = item["ea"]
        item_ea_hex = hex(item_ea) if isinstance(item_ea, int) else str(item_ea)
        assert item_ea_hex.lower() == expected["ea"].lower()
        return item

    return _get


@pytest.fixture
def tool_caller(instance_port):
    """返回 HTTP 工具调用函数。"""
    if not _is_gateway_proxy_available():
        pytest.skip("Gateway proxy not available")

    def caller(tool_name: str, params: Optional[dict] = None, **kwargs) -> Any:
        call_params = {**(params or {}), **kwargs}
        route_port = call_params.get("port")
        selected_port = route_port if isinstance(route_port, int) else instance_port
        return call_tool_gateway(tool_name, call_params, selected_port)

    return caller


# ============================================================================
# 前置信息 Fixtures（Session 级别缓存）
# ============================================================================


@pytest.fixture(scope="session")
def metadata(instance_port) -> Dict[str, Any]:
    """获取 IDB 元数据（缓存）。"""
    result = call_tool_gateway("get_metadata", {}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot get metadata: {result['error']}")
    return result


@pytest.fixture(scope="session")
def functions_cache(instance_port) -> List[Dict[str, Any]]:
    """获取函数列表缓存（前 100 个）。"""
    # 显式传递所有参数以兼容签名问题
    result = call_tool_gateway(
        "list_functions", {"offset": 0, "count": 100}, instance_port
    )
    if "error" in result:
        pytest.skip(f"Cannot list functions: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def strings_cache(instance_port) -> List[Dict[str, Any]]:
    """获取字符串列表缓存（前 100 个）。"""
    # 显式传递所有参数以兼容签名问题
    result = call_tool_gateway("list_strings", {"offset": 0, "count": 100}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot list strings: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def globals_cache(instance_port) -> List[Dict[str, Any]]:
    """获取全局变量列表缓存。"""
    # 工具名为 "list_globals"（与 IDA API 一致）
    result = call_tool_gateway("list_globals", {"offset": 0, "count": 1000}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot list globals: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def entry_points_cache(instance_port) -> List[Dict[str, Any]]:
    """获取入口点缓存。"""
    result = call_tool_gateway("get_entry_points", {}, instance_port)
    if "error" in result:
        return []  # 入口点可能为空，不跳过测试
    return result.get("items", [])


@pytest.fixture(scope="session")
def local_types_cache(instance_port) -> List[Dict[str, Any]]:
    """获取本地类型缓存。"""
    result = call_tool_gateway("list_local_types", {}, instance_port)
    if "error" in result:
        return []  # 类型可能为空，不跳过测试
    return result.get("items", [])


# ============================================================================
# 便捷的单项 Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def first_function(complex_baseline, baseline_function) -> Dict[str, Any]:
    """获取默认测试函数。固定到 complex fixture，避免依赖 IDA 列表排序。"""
    name = complex_baseline["memory"]["default_function"]
    return baseline_function(name)


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
def first_string(complex_baseline, baseline_string) -> Dict[str, Any]:
    """获取默认测试字符串。固定到 complex sentinel。"""
    text = complex_baseline["memory"]["default_string"]
    return baseline_string(text)


@pytest.fixture(scope="session")
def first_string_address(first_string) -> int:
    """获取第一个字符串的地址。"""
    addr = first_string["ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def first_global(complex_baseline, baseline_global) -> Dict[str, Any]:
    """获取默认测试全局变量。固定到可安全改名/改类型的 sink。"""
    name = complex_baseline["memory"]["default_global"]
    return baseline_global(name)


@pytest.fixture(scope="session")
def first_global_address(first_global) -> int:
    """获取第一个全局变量的地址。"""
    addr = first_global["ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def main_function(baseline_function) -> Optional[Dict[str, Any]]:
    """获取 complex fixture 的 main 函数。"""
    return baseline_function("main")


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
    config.addinivalue_line("markers", "modeling: 建模工具测试")
    config.addinivalue_line("markers", "lifecycle: IDA 生命周期管理测试")
    config.addinivalue_line("markers", "destructive: closes or mutates external processes")


def pytest_sessionfinish(session, exitstatus):
    """测试结束时保存 API 日志。"""
    _save_api_log()
