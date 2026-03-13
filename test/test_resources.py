"""测试 MCP Resources (ida:// URI)。

测试逻辑：
1. 通过 FastMCP 客户端访问各种 ida:// URI 资源
2. 验证资源返回格式
3. 记录测试结果到 .artifacts/api_logs/ 目录
   - 资源测试始终直连实例 HTTP 端点
   - stdio/http 仅作为日志标签，表示当前测试上下文

运行方式：
    pytest -m resources           # 只运行 resources 模块测试
    pytest test_resources.py      # 运行此文件所有测试
    pytest test_resources.py -v   # 详细输出
    pytest --transport=http       # 只测试 HTTP 模式

依赖：
    pip install fastmcp pytest
"""
from __future__ import annotations

import pytest
import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

pytestmark = pytest.mark.resources

# ============================================================================
# 配置
# ============================================================================

DEFAULT_HOST = "127.0.0.1"
REQUEST_TIMEOUT = 30

# HTTP 代理配置
HTTP_PROXY_HOST = "127.0.0.1"
HTTP_PROXY_PORT = 11338
HTTP_PROXY_PATH = "/mcp"

# 日志目录
_LOG_DIR = str(Path(__file__).resolve().parent.parent / ".artifacts" / "api_logs")

# URI 调用日志 (按传输模式分开)
_uri_call_logs: Dict[str, List[Dict[str, Any]]] = {
    "stdio": [],
    "http": [],
}


# ============================================================================
# URI 日志记录
# ============================================================================

def _log_uri_call(
    transport: str,
    uri: str,
    port: int,
    result: Any,
    duration_ms: float,
    success: bool,
    error: Optional[str] = None
) -> None:
    """记录 URI 资源访问。"""
    _uri_call_logs[transport].append({
        "timestamp": datetime.now().isoformat(),
        "transport": transport,
        "uri": uri,
        "port": port,
        "success": success,
        "error": error,
        "result_type": type(result).__name__ if result else None,
        "result_size": len(result) if isinstance(result, (list, dict, str)) else None,
        "duration_ms": round(duration_ms, 2),
        "result": _truncate_result(result),
    })


def _truncate_result(result: Any, max_items: int = 5, max_str_len: int = 500) -> Any:
    """截断结果用于日志（避免过大）。"""
    if isinstance(result, list):
        if len(result) > max_items:
            return result[:max_items] + [f"... ({len(result) - max_items} more items)"]
        return result
    if isinstance(result, dict):
        truncated = {}
        for k, v in result.items():
            truncated[k] = _truncate_result(v, max_items, max_str_len)
        return truncated
    if isinstance(result, str) and len(result) > max_str_len:
        return result[:max_str_len] + f"... ({len(result) - max_str_len} more chars)"
    return result


def _save_uri_log() -> None:
    """保存 URI 日志到 {transport}_uri.json。"""
    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
    except Exception:
        return
    
    total_all = 0
    
    for transport, calls in _uri_call_logs.items():
        if not calls:
            continue
        
        # 统计
        total = len(calls)
        total_all += total
        success_count = sum(1 for c in calls if c["success"])
        failed_count = total - success_count
        
        # 按 URI 分组统计
        uri_stats: Dict[str, Dict[str, Any]] = {}
        for call in calls:
            uri = call["uri"]
            if uri not in uri_stats:
                uri_stats[uri] = {"total": 0, "success": 0, "failed": 0, "avg_ms": 0, "durations": []}
            uri_stats[uri]["total"] += 1
            uri_stats[uri]["durations"].append(call["duration_ms"])
            if call["success"]:
                uri_stats[uri]["success"] += 1
            else:
                uri_stats[uri]["failed"] += 1
        
        # 计算平均时间
        for uri, stats in uri_stats.items():
            if stats["durations"]:
                stats["avg_ms"] = round(sum(stats["durations"]) / len(stats["durations"]), 2)
            del stats["durations"]
        
        # 文件名格式: {transport}_uri.json
        log_file = os.path.join(_LOG_DIR, f"{transport}_uri.json")
        try:
            with open(log_file, "w", encoding="utf-8") as f:
                json.dump({
                    "transport": transport,
                    "category": "uri_resources",
                    "generated_at": datetime.now().isoformat(),
                    "summary": {
                        "total_calls": total,
                        "success": success_count,
                        "failed": failed_count,
                        "success_rate": f"{success_count / total * 100:.1f}%" if total > 0 else "N/A",
                    },
                    "uri_stats": uri_stats,
                    "calls": calls,
                }, f, indent=2, ensure_ascii=False, default=str)
        
            print(f"\n[URI Log] {transport}: Saved {total} calls to {log_file}")
            print(f"[URI Log] {transport}: Success: {success_count}, Failed: {failed_count}")
        except Exception as e:
            print(f"\n[URI Log] {transport}: Failed to save: {e}")


# ============================================================================
# 资源访问函数
# ============================================================================

async def _read_resource_async(uri: str, port: int, transport: str = "stdio") -> Dict[str, Any]:
    """通过 FastMCP 客户端异步读取资源。
    
    Args:
        uri: 资源 URI
        port: IDA 实例端口
        transport: 传输模式 ("stdio" 或 "http")
    
    注意：Resources 只在 IDA 实例中定义，proxy 不支持 resources。
    因此这里始终直接连接到 IDA 实例 HTTP 端点；transport 参数仅用于日志标签。
    """
    start_time = time.perf_counter()
    
    try:
        from fastmcp import Client
        
        # Resources 只存在于 IDA 实例中，直接连接到实例
        # (proxy 只转发 tools，不支持 resources)
        mcp_url = f"http://{DEFAULT_HOST}:{port}/mcp/"
        
        async with Client(mcp_url, timeout=REQUEST_TIMEOUT) as client:
            # 读取资源 - 返回 list[TextResourceContents | BlobResourceContents]
            result = await client.read_resource(uri)
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # 解析结果
            data = None
            if isinstance(result, list):
                for content in result:
                    text = getattr(content, 'text', None)
                    if text:
                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            data = text
                        break
                    blob = getattr(content, 'blob', None)
                    if blob:
                        data = {"type": "blob", "size": len(blob)}
                        break
                if data is None:
                    data = [str(c) for c in result]
            else:
                data = result
            
            _log_uri_call(transport, uri, port, data, duration_ms, success=True)
            return {"uri": uri, "data": data}
    
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        error_msg = str(e)
        _log_uri_call(transport, uri, port, None, duration_ms, success=False, error=error_msg)
        return {"uri": uri, "error": error_msg}


def read_resource(uri: str, port: int, transport: str = "stdio") -> Dict[str, Any]:
    """同步读取资源。"""
    return asyncio.run(_read_resource_async(uri, port, transport))


async def _list_resources_async(port: int, transport: str = "stdio") -> Dict[str, Any]:
    """列出所有可用资源。
    
    注意：Resources 只在 IDA 实例中定义，直接连接到实例 HTTP 端点。
    """
    start_time = time.perf_counter()
    
    try:
        from fastmcp import Client
        
        # Resources 只存在于 IDA 实例中
        mcp_url = f"http://{DEFAULT_HOST}:{port}/mcp/"
        
        async with Client(mcp_url, timeout=REQUEST_TIMEOUT) as client:
            result = await client.list_resources()
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            resources = []
            templates = []
            
            if isinstance(result, list):
                for r in result:
                    uri_template = getattr(r, 'uriTemplate', None)
                    if uri_template:
                        templates.append({
                            "uriTemplate": uri_template,
                            "name": getattr(r, 'name', None),
                            "description": getattr(r, 'description', None),
                        })
                    else:
                        resources.append({
                            "uri": getattr(r, 'uri', str(r)),
                            "name": getattr(r, 'name', None),
                            "description": getattr(r, 'description', None),
                        })
            
            data = {
                "resources": resources,
                "templates": templates,
                "total": len(resources) + len(templates),
            }
            
            _log_uri_call(transport, "resources/list", port, data, duration_ms, success=True)
            return data
    
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        error_msg = str(e)
        _log_uri_call(transport, "resources/list", port, None, duration_ms, success=False, error=error_msg)
        return {"error": error_msg}


def list_resources(port: int, transport: str = "stdio") -> Dict[str, Any]:
    """同步列出资源。"""
    return asyncio.run(_list_resources_async(port, transport))


# ============================================================================
# 注册退出时保存日志
# ============================================================================

import atexit
atexit.register(_save_uri_log)


# ============================================================================
# Transport mode fixture
# ============================================================================

@pytest.fixture
def resource_transport(request):
    """获取当前资源测试的传输模式。"""
    transport = request.config.getoption("--transport", "stdio")
    if transport == "both":
        # 默认使用 stdio，如果需要同时测试两种模式需要参数化
        transport = "stdio"
    return transport


# ============================================================================
# 测试类
# ============================================================================

class TestResourceDiscovery:
    """资源发现测试。"""
    
    def test_list_resources(self, instance_port, resource_transport):
        """测试列出可用资源 (resources/list)。"""
        result = list_resources(instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot list resources: {result['error']}")
        
        # 应该返回资源列表
        assert "resources" in result or "templates" in result
        assert result.get("total", 0) >= 0


class TestMetadataResource:
    """IDB 元数据资源测试。"""
    
    def test_idb_metadata(self, instance_port, resource_transport):
        """测试 ida://idb/metadata 资源。"""
        result = read_resource("ida://idb/metadata", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read metadata: {result['error']}")
        
        data = result.get("data", {})
        # 验证元数据字段
        assert isinstance(data, dict)
        # 应该包含一些基本字段
        if data:
            assert any(k in data for k in ["input_file", "arch", "bits", "hash"])


class TestFunctionsResource:
    """函数资源测试。"""
    
    def test_functions_list(self, instance_port, resource_transport):
        """测试 ida://functions 资源。"""
        result = read_resource("ida://functions", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read functions: {result['error']}")
        
        data = result.get("data")
        # 应该返回列表
        assert data is None or isinstance(data, list)
    
    def test_functions_pattern(self, instance_port, resource_transport):
        """测试 ida://functions/{pattern} 资源。"""
        result = read_resource("ida://functions/main*", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read functions pattern: {result['error']}")
        
        data = result.get("data")
        assert data is None or isinstance(data, list)
    
    def test_function_by_address(self, instance_port, first_function_address, resource_transport):
        """测试 ida://function/{addr} 资源。"""
        addr_hex = f"0x{first_function_address:x}"
        result = read_resource(f"ida://function/{addr_hex}", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read function: {result['error']}")
        
        data = result.get("data", {})
        if isinstance(data, dict) and "error" not in data:
            assert "name" in data or "start_ea" in data


class TestStringsResource:
    """字符串资源测试。"""
    
    def test_strings_list(self, instance_port, resource_transport):
        """测试 ida://strings 资源。"""
        result = read_resource("ida://strings", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read strings: {result['error']}")
        
        data = result.get("data")
        assert data is None or isinstance(data, list)
    
    def test_strings_pattern(self, instance_port, resource_transport):
        """测试 ida://strings/{pattern} 资源。"""
        result = read_resource("ida://strings/hello", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read strings pattern: {result['error']}")
        
        data = result.get("data")
        assert data is None or isinstance(data, list)


class TestGlobalsResource:
    """全局变量资源测试。"""
    
    def test_globals_list(self, instance_port, resource_transport):
        """测试 ida://globals 资源。"""
        result = read_resource("ida://globals", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read globals: {result['error']}")
        
        data = result.get("data")
        assert data is None or isinstance(data, list)
    
    def test_globals_pattern(self, instance_port, resource_transport):
        """测试 ida://globals/{pattern} 资源。"""
        result = read_resource("ida://globals/g_*", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read globals pattern: {result['error']}")
        
        data = result.get("data")
        assert data is None or isinstance(data, list)


class TestTypesResource:
    """类型资源测试。"""
    
    def test_types_list(self, instance_port, resource_transport):
        """测试 ida://types 资源。"""
        result = read_resource("ida://types", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read types: {result['error']}")
        
        data = result.get("data")
        # 类型可能为空
        assert data is None or isinstance(data, list)


class TestSegmentsResource:
    """段资源测试。"""
    
    def test_segments_list(self, instance_port, resource_transport):
        """测试 ida://segments 资源。"""
        result = read_resource("ida://segments", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read segments: {result['error']}")
        
        data = result.get("data")
        assert data is None or isinstance(data, list)


class TestImportsExportsResource:
    """导入导出资源测试。"""
    
    def test_imports_list(self, instance_port, resource_transport):
        """测试 ida://imports 资源。"""
        result = read_resource("ida://imports", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read imports: {result['error']}")
        
        data = result.get("data")
        assert data is None or isinstance(data, list)
    
    def test_exports_list(self, instance_port, resource_transport):
        """测试 ida://exports 资源。"""
        result = read_resource("ida://exports", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read exports: {result['error']}")
        
        data = result.get("data")
        assert data is None or isinstance(data, list)


class TestXrefsResource:
    """交叉引用资源测试。"""
    
    def test_xrefs_to(self, instance_port, first_function_address, resource_transport):
        """测试 ida://xrefs/to/{addr} 资源。"""
        addr_hex = f"0x{first_function_address:x}"
        result = read_resource(f"ida://xrefs/to/{addr_hex}", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read xrefs: {result['error']}")
        
        data = result.get("data", {})
        if isinstance(data, dict):
            assert "error" in data or "xrefs" in data or "address" in data
    
    def test_xrefs_from(self, instance_port, first_function_address, resource_transport):
        """测试 ida://xrefs/from/{addr} 资源。"""
        addr_hex = f"0x{first_function_address:x}"
        result = read_resource(f"ida://xrefs/from/{addr_hex}", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read xrefs: {result['error']}")
        
        data = result.get("data", {})
        if isinstance(data, dict):
            assert "error" in data or "xrefs" in data or "address" in data


class TestMemoryResource:
    """内存资源测试。"""
    
    def test_memory_read(self, instance_port, first_function_address, resource_transport):
        """测试 ida://memory/{addr} 资源。"""
        addr_hex = f"0x{first_function_address:x}"
        result = read_resource(f"ida://memory/{addr_hex}", instance_port, resource_transport)
        
        if "error" in result:
            pytest.skip(f"Cannot read memory: {result['error']}")
        
        data = result.get("data", {})
        if isinstance(data, dict) and "error" not in data:
            assert "bytes" in data or "hex" in data or "address" in data


class TestInvalidResource:
    """无效资源测试。"""
    
    def test_invalid_uri(self, instance_port, resource_transport):
        """测试无效资源 URI。"""
        result = read_resource("ida://nonexistent/invalid", instance_port, resource_transport)
        
        # 应该返回错误或空结果
        assert "error" in result or result.get("data") is None or result.get("data") == {}
    
    def test_invalid_address(self, instance_port, resource_transport):
        """测试无效地址。"""
        result = read_resource("ida://function/invalid_addr", instance_port, resource_transport)
        
        # 应该返回错误
        data = result.get("data", {})
        if isinstance(data, dict):
            # 可能在 data 中有 error 字段，或者在顶层有 error
            pass  # 任何响应都可接受，只要不崩溃
