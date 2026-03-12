"""IDA-MCP 配置管理模块。

读取 config.conf 配置文件，提供所有可配置项的访问。

配置项
====================
传输方式开关:
    - enable_stdio: 是否启用 stdio 模式 (默认 false)
    - enable_http: 是否启用 HTTP 代理模式 (默认 true)

协调器配置 (内部组件，地址固定为 127.0.0.1):
    - coordinator_port: 协调器端口 (默认 11337)

HTTP 代理配置:
    - http_host: HTTP 代理监听地址 (默认 127.0.0.1)
    - http_port: HTTP 代理端口 (默认 11338)
    - http_path: MCP 端点路径 (默认 /mcp)

IDA 实例配置 (内部组件，地址固定为 127.0.0.1):
    - ida_default_port: IDA 实例 MCP 端口起始值 (默认 10000)

通用配置:
    - request_timeout: 请求超时时间 (默认 30 秒)
    - debug: 是否启用调试日志 (默认 false)
"""
from __future__ import annotations

import os
from typing import Any, Dict

# 配置文件路径
_CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.conf")

# 默认配置
_DEFAULT_CONFIG = {
    # 传输方式开关
    "enable_stdio": False,   # 是否启用 stdio 模式（协调器）
    "enable_http": True,    # 是否启用 HTTP 代理模式
    
    # 协调器配置（地址固定为 127.0.0.1，仅端口可配置）
    "coordinator_port": 11337,
    
    # HTTP 代理配置
    "http_host": "127.0.0.1",
    "http_port": 11338,
    "http_path": "/mcp",
    
    # IDA 实例配置（地址固定为 127.0.0.1，仅端口可配置）
    "ida_default_port": 10000,
    "ida_path": None, # IDA 可执行文件路径
    
    # 通用配置
    "request_timeout": 30,
    "debug": False,
}

# 缓存的配置
_cached_config: Dict[str, Any] | None = None


def _parse_value(value: str) -> Any:
    """解析配置值，支持字符串、整数、布尔值。"""
    value = value.strip()
    
    # 去除引号
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    
    # 布尔值
    if value.lower() in ("true", "yes", "on", "1"):
        return True
    if value.lower() in ("false", "no", "off", "0"):
        return False
    
    # 整数
    try:
        return int(value)
    except ValueError:
        pass
    
    # 浮点数
    try:
        return float(value)
    except ValueError:
        pass
    
    return value


def load_config(reload: bool = False) -> Dict[str, Any]:
    """加载配置文件。
    
    参数:
        reload: 是否强制重新加载
    
    返回:
        配置字典
    """
    global _cached_config
    
    if _cached_config is not None and not reload:
        return _cached_config
    
    config = dict(_DEFAULT_CONFIG)
    
    if os.path.exists(_CONFIG_FILE):
        try:
            with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # 跳过空行和注释
                    if not line or line.startswith("#"):
                        continue
                    
                    # 解析 key = value
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        
                        # 去除行尾注释
                        if "#" in value:
                            value = value.split("#", 1)[0]
                        
                        value = _parse_value(value)
                        config[key] = value
        except Exception:
            pass
    
    _cached_config = config
    return config


# ============================================================================
# 协调器配置访问函数
# ============================================================================

# 协调器是纯内部组件，地址固定为 127.0.0.1
_COORDINATOR_HOST = "127.0.0.1"


def get_coordinator_host() -> str:
    """获取协调器监听地址（固定为 127.0.0.1，不可配置）。"""
    return _COORDINATOR_HOST


def get_coordinator_port() -> int:
    """获取协调器端口。"""
    config = load_config()
    return int(config.get("coordinator_port", 11337))


def get_coordinator_url() -> str:
    """获取协调器连接 URL。"""
    return f"http://{_COORDINATOR_HOST}:{get_coordinator_port()}"


# ============================================================================
# HTTP 代理配置访问函数
# ============================================================================

def get_http_host() -> str:
    """获取 HTTP 代理监听地址。"""
    config = load_config()
    return str(config.get("http_host", "127.0.0.1"))


def get_http_port() -> int:
    """获取 HTTP 代理监听端口。"""
    config = load_config()
    return int(config.get("http_port", 11338))


def get_http_path() -> str:
    """获取 HTTP MCP 端点路径。"""
    config = load_config()
    return str(config.get("http_path", "/mcp"))


def get_http_url() -> str:
    """获取完整的 HTTP 代理 URL。"""
    host = get_http_host()
    port = get_http_port()
    path = get_http_path()
    return f"http://{host}:{port}{path}"


# ============================================================================
# IDA 实例配置访问函数
# ============================================================================

# IDA 实例是内部组件，地址固定为 127.0.0.1
_IDA_HOST = "127.0.0.1"


def get_ida_host() -> str:
    """获取 IDA 实例 MCP 服务器监听地址（固定为 127.0.0.1，不可配置）。"""
    return _IDA_HOST


def get_ida_default_port() -> int:
    """获取 IDA 实例 MCP 端口起始值。"""
    config = load_config()
    return int(config.get("ida_default_port", 10000))


import subprocess

def _win_to_wsl_path(path: str) -> str:
    """Convert Windows path to WSL path if running in WSL."""
    if not path:
        return path
    if not os.path.exists("/proc/version"):
        return path
        
    try:
        with open("/proc/version", "r") as f:
            if "microsoft" not in f.read().lower():
                return path
    except Exception:
        return path
        
    try:
        # Convert Windows path to WSL path
        result = subprocess.check_output(["wslpath", "-u", path], stderr=subprocess.DEVNULL)
        return result.decode().strip()
    except Exception:
        return path

def get_ida_path() -> str | None:
    """获取 IDA 可执行文件路径。
    
    优先级:
    1. 环境变量 IDA_PATH
    2. 配置文件中的 ida_path
    3. None
    
    如果在 WSL 环境中，会自动将 Windows 路径转换为 WSL 路径。
    """
    path = None
    env_path = os.getenv("IDA_PATH")
    if env_path:
        path = env_path
    else:
        config = load_config()
        path = config.get("ida_path")
        
    if path:
        return _win_to_wsl_path(path)
    return None



# ============================================================================
# 通用配置访问函数
# ============================================================================

def get_request_timeout() -> int:
    """获取请求超时时间（秒）。"""
    config = load_config()
    return int(config.get("request_timeout", 30))


def is_debug_enabled() -> bool:
    """是否启用调试日志。"""
    config = load_config()
    return bool(config.get("debug", False))


# ============================================================================
# 传输方式开关
# ============================================================================

def is_stdio_enabled() -> bool:
    """是否启用 stdio 模式（协调器）。"""
    config = load_config()
    return bool(config.get("enable_stdio", False))


def is_http_enabled() -> bool:
    """是否启用 HTTP 代理模式。"""
    config = load_config()
    return bool(config.get("enable_http", True))
