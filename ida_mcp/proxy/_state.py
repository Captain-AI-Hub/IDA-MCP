"""状态管理 - 实例选择和转发。"""
from __future__ import annotations

from typing import Optional, Any, List

import sys
import os
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

from _http import http_get, http_post  # type: ignore

# 当前选中的端口
_current_port: Optional[int] = None


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


def get_current_port() -> Optional[int]:
    """获取当前端口。"""
    return _current_port


def set_current_port(port: int) -> None:
    """设置当前端口。"""
    global _current_port
    _current_port = port


def clear_current_port() -> None:
    """清除当前端口。"""
    global _current_port
    _current_port = None


def ensure_port() -> Optional[int]:
    """确保有可用的目标端口。
    
    返回:
        有效端口号，或 None 表示没有可用实例。
    """
    global _current_port
    
    # 已有有效端口，验证是否仍然注册
    if is_valid_port(_current_port):
        if is_registered_port(int(_current_port)):  # type: ignore
            return int(_current_port)  # type: ignore
        # 端口不再有效，清除
        _current_port = None
    
    # 从协调器获取当前选中
    res = http_get('/current_instance')
    if isinstance(res, dict) and is_valid_port(res.get('port')):
        port = int(res['port'])
        if is_registered_port(port):
            _current_port = port
            return _current_port
    
    # 请求协调器自动选择
    res = http_post('/select_instance', {})
    if isinstance(res, dict) and is_valid_port(res.get('selected_port')):
        port = int(res['selected_port'])
        if is_registered_port(port):
            _current_port = port
            return _current_port
    
    # 尝试选择第一个可用实例
    instances = get_instances()
    if instances:
        first_port = instances[0].get('port')
        if isinstance(first_port, int) and is_valid_port(first_port):
            _current_port = first_port
            return _current_port
    
    # 没有可用实例
    return None


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
            return {"error": f"Invalid port: {port}. Port must be 1-65535."}
        if not is_registered_port(port):
            return {"error": f"Port {port} not found in registered instances. Use list_instances to check available instances."}
        target_port = port
    else:
        # 自动选择端口
        target_port = ensure_port()
        if target_port is None:
            return {"error": "No IDA instances available. Please ensure IDA is running with the MCP plugin loaded."}
    
    # 构造请求
    body: dict = {
        "tool": tool,
        "params": params or {},
        "port": int(target_port)
    }
    if timeout and timeout > 0:
        body["timeout"] = timeout
    # HTTP 层超时需要比协调器内部工具超时更长，留出锁获取+连接建立的余量
    http_timeout = (timeout + 15) if (timeout and timeout > 0) else None
    result = http_post('/call', body, timeout=http_timeout)
    
    # 处理结果
    if result is None:
        return {"error": "Failed to connect to coordinator. Is registry running on 127.0.0.1:11337?"}
    
    # 提取实际数据
    if isinstance(result, dict):
        if 'error' in result:
            return result
        if 'data' in result:
            return result['data']
    
    return result
