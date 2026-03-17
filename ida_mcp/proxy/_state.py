"""状态管理 - 实例选择和转发。"""
from __future__ import annotations

from typing import Optional, Any, List

from ..errors import error_payload, normalize_error_payload
from ._http import http_get, http_post


def get_instances() -> List[dict]:
    """获取所有实例列表。"""
    data = http_get('/instances')
    return data if isinstance(data, list) else []


def is_valid_port(p: Any) -> bool:
    """验证端口格式有效性 (1-65535)。"""
    return isinstance(p, int) and 1 <= p <= 65535


def is_registered_port(port: int) -> bool:
    """验证端口是否对应已注册的实例。"""
    instances = get_instances()
    return any(i.get('port') == port for i in instances)


def choose_port(port: Optional[int] = None) -> Optional[int]:
    """选择目标端口。

    若显式提供 port，则只做有效性验证。
    若未提供，则按无状态策略自动选择：
    1. 优先端口 10000
    2. 否则取最小已注册端口
    """
    if port is not None:
        if not is_valid_port(port):
            return None
        return port if is_registered_port(port) else None

    instances = [i for i in get_instances() if is_valid_port(i.get("port"))]
    if not instances:
        return None

    ports = sorted(int(i.get("port")) for i in instances if is_valid_port(i.get("port")))
    if 10000 in ports:
        return 10000
    return ports[0]


def forward(tool: str, params: Optional[dict] = None, port: Optional[int] = None, timeout: Optional[int] = None) -> Any:
    """统一转发调用到后端。
    
    参数:
        tool: 工具名称
        params: 工具参数
        port: 指定端口 (可选，未指定则使用当前选中的实例)
        timeout: 自定义超时秒数 (可选，未指定则使用默认值)
    
    返回:
        工具调用结果，或错误字典
    """
    # 确定目标端口
    if port is not None:
        # 用户指定了端口，验证有效性
        if not is_valid_port(port):
            return error_payload("invalid_port", f"Invalid port: {port}. Port must be 1-65535.", port=port)
        if not is_registered_port(port):
            return error_payload(
                "instance_not_found",
                f"Port {port} not found in registered instances. Use list_instances to check available instances.",
                port=port,
            )
        target_port = port
    else:
        # 自动选择端口
        target_port = choose_port()
        if target_port is None:
            return error_payload(
                "no_instances",
                "No IDA instances available. Please ensure IDA is running with the MCP plugin loaded.",
            )
    
    # 构造请求
    body: dict = {
        "tool": tool,
        "params": params or {},
        "port": int(target_port)
    }
    if timeout and timeout > 0:
        body["timeout"] = timeout
    # HTTP 层超时需要比网关内部工具超时更长，留出锁获取+连接建立的余量
    http_timeout = (timeout + 15) if (timeout and timeout > 0) else None
    result = http_post('/call', body, timeout=http_timeout)
    
    # 处理结果
    if result is None:
        return error_payload(
            "gateway_unavailable",
            "Failed to connect to gateway. Ensure the standalone gateway is running and reachable.",
        )
    
    # 提取实际数据
    if isinstance(result, dict):
        if 'error' in result:
            return normalize_error_payload(
                result,
                "tool_call_failed",
                f"Gateway rejected proxy call for tool {tool}.",
                tool=tool,
                port=target_port,
            )
        if 'data' in result:
            return result['data']
    
    return result
