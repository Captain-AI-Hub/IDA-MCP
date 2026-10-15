"""pytest 共享 fixtures（桥接直连 + 无头 idalib 实例）。

测试框架设计：
1. ida_instance - 连接或无头启动 test/samples/complex.exe 实例
   （无可用 IDA/idalib 环境时自动跳过后端工具测试）
2. tool_caller - 通过实例桥直接调用后端工具
3. 前置信息 fixtures（session 级别缓存）：metadata / functions_cache /
   strings_cache / globals_cache / first_* 等

运行方式：
    pytest
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# 确保 ida_mcp 包可导入 — 测试位于仓库根目录的 test/
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

import pytest

from ida_mcp import bridge_client, instances, lifecycle

_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
_SAMPLE = Path(__file__).resolve().parent / "samples" / "complex.exe"


def pytest_addoption(parser):
    """添加命令行选项。"""
    parser.addoption(
        "--allow-destructive-lifecycle",
        action="store_true",
        default=False,
        help="Allow lifecycle tests that close a live IDA instance.",
    )
    parser.addoption(
        "--ida-open-timeout",
        type=int,
        default=300,
        help="Headless open/analysis timeout in seconds (default 300).",
    )


# ============================================================================
# 实例 fixture：attach 或无头启动
# ============================================================================


@pytest.fixture(scope="session")
def ida_instance(request) -> Dict[str, Any]:
    """连接 complex.exe 的活跃实例，或无头启动一个 idalib worker。"""
    sample = str(_SAMPLE.resolve())
    existing = instances.find_by_path(sample)
    if existing is not None and bridge_client.is_alive(existing):
        yield existing
        return

    result = lifecycle.open_database(
        sample,
        set_current=False,
        headless="headless",
        wait_for_analysis=True,
        timeout=request.config.getoption("--ida-open-timeout"),
    )
    if "error" in result:
        pytest.skip(f"No live IDA instance and headless open failed: {result['error']}")
        return
    entry = result["instance"]
    yield entry
    try:
        lifecycle.close_database(entry, terminate=True, save=False)
    except Exception:  # noqa: BLE001 - teardown is best effort
        pass


@pytest.fixture
def tool_caller(ida_instance):
    """返回直接调用实例桥的工具函数。"""

    def caller(tool_name: str, params: Optional[dict] = None, **kwargs) -> Any:
        call_params = {**(params or {}), **kwargs}
        timeout = call_params.pop("timeout", None)
        call_params.pop("port", None)
        call_params.pop("instance_id", None)
        try:
            return bridge_client.call_tool(
                ida_instance, tool_name, call_params, timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001 - tests expect error dicts
            described = bridge_client.describe_error(exc)
            if "error" in described:
                return described
            raise

    return caller


# ============================================================================
# 前置信息 Fixtures（Session 级别缓存）
# ============================================================================


@pytest.fixture(scope="session")
def complex_baseline() -> Dict[str, Any]:
    """Loaded baseline harvested from test/samples/complex.exe."""
    with open(_FIXTURE_DIR / "complex_baseline.json", "r", encoding="utf-8") as f:
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


def _session_call(ida_instance, tool: str, params: dict) -> Any:
    return bridge_client.call_tool(ida_instance, tool, params)


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


@pytest.fixture(scope="session")
def metadata(ida_instance) -> Dict[str, Any]:
    result = _session_call(ida_instance, "get_metadata", {})
    if "error" in result:
        pytest.skip(f"Cannot get metadata: {result['error']}")
    return result


@pytest.fixture(scope="session")
def functions_cache(ida_instance) -> List[Dict[str, Any]]:
    result = _session_call(ida_instance, "list_functions", {"offset": 0, "count": 100})
    if "error" in result:
        pytest.skip(f"Cannot list functions: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def strings_cache(ida_instance) -> List[Dict[str, Any]]:
    result = _session_call(ida_instance, "list_strings", {"offset": 0, "count": 100})
    if "error" in result:
        pytest.skip(f"Cannot list strings: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def globals_cache(ida_instance) -> List[Dict[str, Any]]:
    result = _session_call(ida_instance, "list_globals", {"offset": 0, "count": 1000})
    if "error" in result:
        pytest.skip(f"Cannot list globals: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def entry_points_cache(ida_instance) -> List[Dict[str, Any]]:
    result = _session_call(ida_instance, "get_entry_points", {})
    if "error" in result:
        return []
    return result.get("items", [])


@pytest.fixture(scope="session")
def local_types_cache(ida_instance) -> List[Dict[str, Any]]:
    result = _session_call(ida_instance, "list_local_types", {})
    if "error" in result:
        return []
    return result.get("items", [])


# ============================================================================
# 便捷的单项 Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def first_function(complex_baseline, baseline_function) -> Dict[str, Any]:
    name = complex_baseline["memory"]["default_function"]
    return baseline_function(name)


@pytest.fixture(scope="session")
def first_function_address(first_function) -> int:
    addr = first_function["start_ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def first_function_name(first_function) -> str:
    return first_function["name"]


@pytest.fixture(scope="session")
def first_string(complex_baseline, baseline_string) -> Dict[str, Any]:
    text = complex_baseline["memory"]["default_string"]
    return baseline_string(text)


@pytest.fixture(scope="session")
def first_string_address(first_string) -> int:
    addr = first_string["ea"]
    return int(addr, 16) if isinstance(addr, str) else int(addr)


@pytest.fixture(scope="session")
def first_global(complex_baseline, baseline_global) -> Dict[str, Any]:
    name = complex_baseline["memory"]["default_global"]
    return baseline_global(name)


@pytest.fixture(scope="session")
def first_global_address(first_global) -> int:
    addr = first_global["ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def main_function(baseline_function) -> Optional[Dict[str, Any]]:
    return baseline_function("main")


@pytest.fixture(scope="session")
def main_function_address(main_function) -> int:
    if not main_function:
        pytest.skip("No main function found")
    addr = main_function["start_ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


# ============================================================================
# 测试标记
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
    config.addinivalue_line("markers", "modeling: 建模工具测试")
    config.addinivalue_line("markers", "lifecycle: IDA 生命周期管理测试")
    config.addinivalue_line("markers", "destructive: closes or mutates external processes")
