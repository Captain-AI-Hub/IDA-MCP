"""IDA-MCP 配置管理模块。

读取 config.conf 配置文件，提供所有可配置项的访问。

配置项
====================
传输方式开关:
    - enable_stdio: 是否启用 stdio 模式 (默认 false)
    - enable_http: 是否启用 HTTP 代理模式 (默认 true)
    - enable_unsafe: 是否启用 unsafe 工具 (默认 true)

HTTP 代理配置:
    - http_host: 网关监听地址 (默认 127.0.0.1)
    - http_port: 网关监听端口 (默认 11338)
    - http_path: MCP 端点路径 (默认 /mcp)

IDA 实例配置 (内部组件，地址固定为 127.0.0.1):
    - ida_default_port: IDA 实例 MCP 端口起始值 (默认 10000)
    - ida_path: IDA 可执行文件路径
    - open_in_ida_bundle_dir: open_in_ida staging 目录 (可选)

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
    "enable_unsafe": True,  # 是否启用 unsafe 工具
    
    # 协调器配置（已并入网关；保留键用于兼容旧配置）
    "coordinator_port": 11337,
    
    # HTTP 代理配置
    "http_host": "127.0.0.1",
    "http_port": 11338,
    "http_path": "/mcp",
    
    # IDA 实例配置（地址固定为 127.0.0.1，仅端口可配置）
    "ida_default_port": 10000,
    "ida_path": None, # IDA 可执行文件路径
    "open_in_ida_bundle_dir": None, # open_in_ida staging 目录
    
    # 通用配置
    "request_timeout": 30,
    "debug": False,
}

# 缓存的配置
_cached_config: Dict[str, Any] | None = None


def _coerce_bool(value: Any, default: bool) -> bool:
    """将配置值或环境变量值转换为布尔值。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        parsed = _parse_value(value)
        if isinstance(parsed, bool):
            return parsed
        if isinstance(parsed, (int, float)):
            return bool(parsed)
    return default


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


def parse_config_file(path: str) -> Dict[str, Any]:
    """解析任意 config.conf 风格文件。"""
    config: Dict[str, Any] = {}

    if not os.path.exists(path):
        return config

    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                if "#" in value:
                    value = value.split("#", 1)[0]
                config[key.strip()] = _parse_value(value)
    except Exception:
        return {}

    return config


def load_config(reload: bool = False) -> Dict[str, Any]:
    """加载配置文件。"""
    global _cached_config

    if _cached_config is not None and not reload:
        return _cached_config

    config = dict(_DEFAULT_CONFIG)
    config.update(parse_config_file(_CONFIG_FILE))
    _cached_config = config
    return config


# ============================================================================
# 网关 / 协调器配置访问函数
# ============================================================================

def get_http_bind_host() -> str:
    """获取 HTTP 网关监听地址。"""
    config = load_config()
    return str(config.get("http_host", "127.0.0.1"))


def get_http_connect_host() -> str:
    """获取客户端访问 HTTP 网关时应使用的地址。"""
    host = get_http_bind_host().strip()
    if host in {"0.0.0.0", "::", ""}:
        return "127.0.0.1"
    return host


def get_coordinator_host() -> str:
    """获取内部 API 的客户端访问地址。"""
    return get_http_connect_host()


def get_coordinator_port() -> int:
    """获取协调器内部 API 所在端口（与网关端口一致）。"""
    return get_http_port()


def get_coordinator_url() -> str:
    """获取协调器内部 API 基础 URL。"""
    return f"http://{get_http_connect_host()}:{get_http_port()}/internal"


# ============================================================================
# HTTP 代理配置访问函数
# ============================================================================

def get_http_host() -> str:
    """获取 HTTP 网关监听地址。兼容旧调用。"""
    return get_http_bind_host()


def get_http_port() -> int:
    """获取 HTTP 代理监听端口。"""
    config = load_config()
    return int(config.get("http_port", 11338))


def get_http_path() -> str:
    """获取 HTTP MCP 端点路径。"""
    config = load_config()
    return str(config.get("http_path", "/mcp"))


def get_http_url() -> str:
    """获取客户端访问用的完整 HTTP 网关 URL。"""
    host = get_http_connect_host()
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

def get_ida_path() -> str | None:
    """获取 IDA 可执行文件路径。
    
    优先级:
    1. 环境变量 IDA_PATH
    2. 配置文件中的 ida_path
    3. None
    """
    path = None
    env_path = os.getenv("IDA_PATH")
    if env_path:
        path = env_path
    else:
        config = load_config()
        path = config.get("ida_path")
        
    if isinstance(path, str):
        path = path.strip()
        if path:
            return path
    return None


def get_open_in_ida_bundle_dir() -> str | None:
    """获取 open_in_ida 使用的 staging 目录。

    优先级:
    1. 环境变量 IDA_MCP_BUNDLE_DIR
    2. 配置文件中的 open_in_ida_bundle_dir
    3. None
    """
    env_path = os.getenv("IDA_MCP_BUNDLE_DIR")
    if env_path and env_path.strip():
        return env_path.strip()

    config = load_config()
    configured_path = config.get("open_in_ida_bundle_dir")
    if isinstance(configured_path, str):
        configured_path = configured_path.strip()
        if configured_path:
            return configured_path
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


def is_unsafe_enabled() -> bool:
    """是否启用 unsafe 工具。

    优先级:
    1. 环境变量 IDA_MCP_ENABLE_UNSAFE
    2. 配置文件中的 enable_unsafe
    3. 默认值 true
    """
    env_value = os.getenv("IDA_MCP_ENABLE_UNSAFE")
    if env_value is not None:
        return _coerce_bool(env_value, True)

    config = load_config()
    return _coerce_bool(config.get("enable_unsafe", True), True)
