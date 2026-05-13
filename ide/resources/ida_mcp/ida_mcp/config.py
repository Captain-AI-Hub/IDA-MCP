"""IDA-MCP configuration management module.

Reads the config.conf file and provides access to all configurable options.

Configuration Options
====================
Transport switches:
    - enable_stdio: whether to enable stdio mode (default false)
    - enable_http: whether to enable HTTP proxy mode (default true)
    - enable_unsafe: whether to enable unsafe tools (default true)
    - wsl_path_bridge: whether to enable WSL/Windows path bridging (default false)

HTTP proxy config:
    - http_host: gateway bind address (default 127.0.0.1)
    - http_port: gateway listen port (default 11338)
    - http_path: MCP endpoint path (default /mcp)

IDA instance config:
    - ida_default_port: starting port for IDA instance MCP (default 10000)
    - ida_path: IDA executable path
    - ida_python: IDA Python executable path
    - ida_host: IDA instance MCP listen address (default 127.0.0.1)
    - open_in_ida_bundle_dir: open_in_ida staging directory (optional)
    - open_in_ida_autonomous: whether open_in_ida defaults to -A (default true)
    - auto_start: whether to auto-start the instance service after plugin load (default false)
    - server_name: MCP service name (default IDA-MCP)

General config:
    - request_timeout: request timeout in seconds (default 30)
    - debug: whether to enable debug logging (default false)
"""

from __future__ import annotations

import os
from typing import Any, Dict

# config file path
_CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.conf")

# default configuration
_DEFAULT_CONFIG = {
    # transport switches
    "enable_stdio": False,  # whether to enable stdio mode (coordinator)
    "enable_http": True,  # whether to enable HTTP proxy mode
    "enable_unsafe": True,  # whether to enable unsafe tools
    "wsl_path_bridge": False,  # whether to enable WSL/Windows path bridging
    # HTTP proxy config
    "http_host": "127.0.0.1",
    "http_port": 11338,
    "http_path": "/mcp",
    # IDA instance config
    "ida_default_port": 10000,
    "ida_path": None,  # IDA executable path
    "ida_python": None,  # IDA Python executable path
    "ida_host": "127.0.0.1",  # IDA instance MCP listen address
    "open_in_ida_bundle_dir": None,  # open_in_ida staging directory
    "open_in_ida_autonomous": True,  # whether open_in_ida defaults to appending -A
    "auto_start": False,  # whether to auto-start instance service after plugin load
    "server_name": "IDA-MCP",  # MCP service name
    # general config
    "request_timeout": 30,
    "debug": False,
}

# cached configuration
_cached_config: Dict[str, Any] | None = None


def _coerce_bool(value: Any, default: bool) -> bool:
    """Coerce a config value to boolean."""
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
    """Parse a config value, supporting strings, integers, and booleans."""
    value = value.strip()

    # strip quotes
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]

    # booleans
    if value.lower() in ("true", "yes", "on", "1"):
        return True
    if value.lower() in ("false", "no", "off", "0"):
        return False

    # integers
    try:
        return int(value)
    except ValueError:
        pass

    # floats
    try:
        return float(value)
    except ValueError:
        pass

    return value


def _split_value_and_comment(text: str) -> tuple[str, str]:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char == "#":
            return text[:index].rstrip(), text[index:].rstrip()
    return text.rstrip(), ""


def parse_config_file(path: str) -> Dict[str, Any]:
    """Parse any config.conf-style file."""
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
                value, _comment = _split_value_and_comment(value)
                config[key.strip()] = _parse_value(value)
    except Exception:
        return {}

    return config


def load_config(reload: bool = False) -> Dict[str, Any]:
    """Load the configuration file."""
    global _cached_config

    if _cached_config is not None and not reload:
        return _cached_config

    config = dict(_DEFAULT_CONFIG)
    config.update(parse_config_file(_CONFIG_FILE))
    _cached_config = config
    return config


# ============================================================================
# Gateway internal API config accessors
# ============================================================================


def get_http_bind_host() -> str:
    """Get the HTTP gateway bind address."""
    config = load_config()
    return str(config.get("http_host", "127.0.0.1"))


def get_http_connect_host() -> str:
    """Get the address clients should use to reach the HTTP gateway."""
    host = get_http_bind_host().strip()
    if host in {"0.0.0.0", "::", ""}:
        return "127.0.0.1"
    return host


def get_gateway_internal_host() -> str:
    """Get the client-facing address for the gateway internal API."""
    return get_http_connect_host()


def get_gateway_internal_port() -> int:
    """Get the gateway internal API port (same as the gateway port)."""
    return get_http_port()


def get_gateway_internal_url() -> str:
    """Get the gateway internal API base URL."""
    return f"http://{get_http_connect_host()}:{get_http_port()}/internal"


# ============================================================================
# HTTP proxy config accessors
# ============================================================================


def get_http_port() -> int:
    """Get the HTTP proxy listen port."""
    config = load_config()
    return int(config.get("http_port", 11338))


def get_http_path() -> str:
    """Get the HTTP MCP endpoint path."""
    config = load_config()
    return str(config.get("http_path", "/mcp"))


def get_http_url() -> str:
    """Get the full HTTP gateway URL for client access."""
    host = get_http_connect_host()
    port = get_http_port()
    path = get_http_path()
    return f"http://{host}:{port}{path}"


# ============================================================================
# IDA instance config accessors
# ============================================================================


def get_ida_host() -> str:
    """Get the IDA instance MCP server listen address."""
    config = load_config()
    host = str(config.get("ida_host", "127.0.0.1")).strip()
    return host or "127.0.0.1"


def get_ida_default_port() -> int:
    """Get the starting port for IDA instance MCP."""
    config = load_config()
    return int(config.get("ida_default_port", 10000))


def get_ida_path() -> str | None:
    """Get the IDA executable path."""
    config = load_config()
    path = config.get("ida_path")

    if isinstance(path, str):
        path = path.strip()
        if path:
            return path
    return None


def get_ida_python() -> str | None:
    """Get the IDA Python executable path."""
    config = load_config()
    path = config.get("ida_python")

    if isinstance(path, str):
        path = path.strip()
        if path:
            return path
    return None


def get_open_in_ida_bundle_dir() -> str | None:
    """Get the staging directory used by open_in_ida."""
    config = load_config()
    configured_path = config.get("open_in_ida_bundle_dir")
    if isinstance(configured_path, str):
        configured_path = configured_path.strip()
        if configured_path:
            return configured_path
    return None


def is_open_in_ida_autonomous_enabled() -> bool:
    """Whether open_in_ida should default to autonomous mode."""
    config = load_config()
    return _coerce_bool(config.get("open_in_ida_autonomous", True), True)


# ============================================================================
# General config accessors
# ============================================================================


def get_request_timeout() -> int:
    """Get the request timeout in seconds."""
    config = load_config()
    return int(config.get("request_timeout", 30))


def is_debug_enabled() -> bool:
    """Whether debug logging is enabled."""
    config = load_config()
    return bool(config.get("debug", False))


# ============================================================================
# Transport switches
# ============================================================================


def is_stdio_enabled() -> bool:
    """Whether stdio mode (coordinator) is enabled."""
    config = load_config()
    return bool(config.get("enable_stdio", False))


def is_http_enabled() -> bool:
    """Whether HTTP proxy mode is enabled."""
    config = load_config()
    return bool(config.get("enable_http", True))


def is_unsafe_enabled() -> bool:
    """Whether unsafe tools are enabled."""
    config = load_config()
    return _coerce_bool(config.get("enable_unsafe", True), True)


def is_wsl_path_bridge_enabled() -> bool:
    """Whether WSL/Windows path bridging is enabled."""
    config = load_config()
    return _coerce_bool(config.get("wsl_path_bridge", False), False)


def is_auto_start_enabled() -> bool:
    """Whether the instance service auto-starts after plugin load."""
    config = load_config()
    return _coerce_bool(config.get("auto_start", False), False)


def get_server_name() -> str:
    """Get the MCP service name."""
    config = load_config()
    name = str(config.get("server_name", "IDA-MCP")).strip()
    return name or "IDA-MCP"
