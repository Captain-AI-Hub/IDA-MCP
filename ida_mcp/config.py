"""IDA-MCP configuration management module.

Reads the config.conf file and provides access to all configurable options.

Configuration Options
====================
Runtime switches:
    - enable_gateway: whether to enable the gateway and MCP proxy (default true)
    - enable_unsafe: whether to enable unsafe tools (default false)
    - wsl_path_bridge: whether to enable WSL/Windows path bridging (default false)

Gateway HTTP config:
    - http_host: gateway bind address (default 127.0.0.1)
    - http_port: gateway listen port (default 11338)
    - http_path: MCP endpoint path (default /mcp)
    - gateway_token: required shared bearer token; empty fails closed

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

import json
import os
import re
import secrets
import sys
from typing import Any, Dict, Mapping

# config file path
_CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.conf")

# default configuration
_DEFAULT_CONFIG = {
    # runtime switches
    "enable_gateway": True,  # whether to enable the gateway and MCP proxy
    "enable_unsafe": False,  # whether to enable unsafe tools
    "wsl_path_bridge": False,  # whether to enable WSL/Windows path bridging
    # Gateway HTTP config
    "http_host": "127.0.0.1",
    "http_port": 11338,
    "http_path": "/mcp",
    "gateway_token": None,
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

# HCLI-managed settings. HCLI stores these in ida-config.json and the
# ida-settings package exposes them while the plugin is running inside IDA.
_HCLI_SETTING_KEYS = (
    "gateway_token",
    "ida_path",
    "ida_python",
    "auto_start",
    "enable_unsafe",
    "open_in_ida_autonomous",
    "http_host",
    "http_port",
    "http_path",
    "request_timeout",
    "debug",
)
_ENV_PREFIX = "IDA_MCP_CONFIG_"
_AUTO_TOKEN_SENTINEL = "__AUTO_GENERATE_GATEWAY_TOKEN__"
_AUTO_PYTHON_SENTINELS = {"auto", "detect", "auto-detect"}

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


def _coerce_int_range(value: Any, default: int, minimum: int, maximum: int) -> int:
    """Coerce an integer config value and clamp invalid values to default."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if minimum <= parsed <= maximum:
        return parsed
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


def _environment_overrides() -> Dict[str, Any]:
    """Read settings forwarded to the standalone gateway process."""
    overrides: Dict[str, Any] = {}
    for key in _HCLI_SETTING_KEYS:
        value = os.environ.get(f"{_ENV_PREFIX}{key.upper()}")
        if value is not None:
            overrides[key] = _parse_value(value)
    return overrides


def _hcli_setting_overrides() -> Dict[str, Any]:
    """Read HCLI settings when called from an installed IDA plugin."""
    try:
        import ida_settings  # type: ignore
    except (ImportError, ModuleNotFoundError):
        return {}

    overrides: Dict[str, Any] = {}
    for key in _HCLI_SETTING_KEYS:
        try:
            value = ida_settings.get_current_plugin_setting(key)
        except (KeyError, RuntimeError, ValueError, OSError):
            continue
        except Exception:
            # Configuration must remain usable if ida-settings changes or is
            # unavailable in a standalone child process.
            continue
        if isinstance(value, str) and not value.strip():
            continue
        overrides[key] = value
    return overrides



def _set_hcli_setting(key: str, value: str | bool) -> bool:
    """Persist a setting through HCLI's shared ida-config.json store."""
    try:
        import ida_settings  # type: ignore

        ida_settings.set_current_plugin_setting(key, value)
        return True
    except Exception:
        return False


def _write_config_string(key: str, value: str) -> bool:
    """Fallback persistence for non-HCLI/manual plugin installations."""
    try:
        with open(_CONFIG_FILE, "r", encoding="utf-8", newline="") as handle:
            lines = handle.readlines()
    except OSError:
        return False

    encoded = json.dumps(value, ensure_ascii=False)
    replaced = False
    output: list[str] = []
    for line in lines:
        ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        body = line[: -len(ending)] if ending else line
        stripped = body.lstrip()
        if not replaced and re.match(rf"^{re.escape(key)}\s*=", stripped):
            indent = body[: len(body) - len(stripped)]
            _value, comment = _split_value_and_comment(stripped.split("=", 1)[1])
            suffix = f" {comment}" if comment else ""
            output.append(f"{indent}{key} = {encoded}{suffix}{ending}")
            replaced = True
        else:
            output.append(line)

    if not replaced:
        output.append(f"{key} = {encoded}\n")
    try:
        with open(_CONFIG_FILE, "w", encoding="utf-8", newline="") as handle:
            handle.writelines(output)
        return True
    except OSError:
        return False


def _persist_string_setting(key: str, value: str) -> bool:
    return _set_hcli_setting(key, value) or _write_config_string(key, value)


def _detect_running_ida_python() -> str | None:
    """Resolve the Python executable backing the current IDAPython runtime."""
    candidates: list[str] = []
    for prefix in (
        getattr(sys, "exec_prefix", None),
        getattr(sys, "base_prefix", None),
        getattr(sys, "prefix", None),
    ):
        if not prefix:
            continue
        if os.name == "nt":
            candidates.append(os.path.join(prefix, "python.exe"))
        else:
            candidates.extend(
                [
                    os.path.join(prefix, "bin", "python3"),
                    os.path.join(prefix, "bin", "python"),
                ]
            )

    executable = getattr(sys, "executable", "")
    if executable and os.path.basename(executable).lower().startswith("python"):
        candidates.append(executable)

    seen: set[str] = set()
    for candidate in candidates:
        normalized = os.path.normcase(os.path.abspath(candidate))
        if normalized in seen:
            continue
        seen.add(normalized)
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return None


def initialize_runtime_settings() -> Dict[str, Any]:
    """Generate first-run secrets and resolve machine-specific HCLI settings."""
    global _cached_config

    config = load_config(reload=True)
    result: Dict[str, Any] = {
        "gateway_token": None,
        "gateway_token_generated": False,
        "ida_python": None,
        "ida_python_detected": False,
    }

    raw_token = config.get("gateway_token")
    token = raw_token.strip() if isinstance(raw_token, str) else ""
    if not token or token == _AUTO_TOKEN_SENTINEL:
        token = secrets.token_urlsafe(32)
        if _persist_string_setting("gateway_token", token):
            result["gateway_token_generated"] = True
    result["gateway_token"] = token

    raw_python = config.get("ida_python")
    python_value = raw_python.strip() if isinstance(raw_python, str) else ""
    if not python_value or python_value.lower() in _AUTO_PYTHON_SENTINELS:
        detected = _detect_running_ida_python()
        if detected:
            python_value = detected
            if _persist_string_setting("ida_python", detected):
                result["ida_python_detected"] = True
    result["ida_python"] = python_value or None

    _cached_config = None
    load_config(reload=True)
    return result


def load_config(reload: bool = False) -> Dict[str, Any]:
    """Load config.conf, gateway environment, and HCLI settings."""
    global _cached_config

    if _cached_config is not None and not reload:
        return _cached_config

    config = dict(_DEFAULT_CONFIG)
    config.update(parse_config_file(_CONFIG_FILE))
    config.update(_environment_overrides())
    config.update(_hcli_setting_overrides())
    _cached_config = config
    return config


def build_subprocess_environment(
    base: Mapping[str, str] | None = None,
) -> Dict[str, str]:
    """Forward effective HCLI settings to the standalone gateway process."""
    environment = dict(os.environ if base is None else base)
    config = load_config()
    for key in _HCLI_SETTING_KEYS:
        value = config.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        if isinstance(value, bool):
            serialized = "true" if value else "false"
        else:
            serialized = str(value)
        environment[f"{_ENV_PREFIX}{key.upper()}"] = serialized
    return environment


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
# Gateway HTTP config accessors
# ============================================================================


def get_http_port() -> int:
    """Get the gateway HTTP listen port."""
    config = load_config()
    return _coerce_int_range(config.get("http_port", 11338), 11338, 1, 65535)


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


def get_gateway_token() -> str | None:
    """Get the shared gateway bearer token.

    The gateway refuses requests when this is unset.  Installers should write a
    random non-empty token into config.conf.
    """
    config = load_config()
    token = config.get("gateway_token")
    if isinstance(token, str):
        token = token.strip()
        if token and token != _AUTO_TOKEN_SENTINEL:
            return token
    return None


def get_gateway_auth_headers() -> dict[str, str]:
    """Get HTTP headers for calls to a token-protected gateway."""
    token = get_gateway_token()
    if not token:
        return {}
    return {
        "Authorization": f"Bearer {token}",
        "X-IDA-MCP-Token": token,
    }


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
    return _coerce_int_range(config.get("ida_default_port", 10000), 10000, 1, 65535)


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
        if path and path.lower() not in _AUTO_PYTHON_SENTINELS:
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
    return _coerce_int_range(config.get("request_timeout", 30), 30, 1, 3600)


def is_debug_enabled() -> bool:
    """Whether debug logging is enabled."""
    config = load_config()
    return bool(config.get("debug", False))


# ============================================================================
# Runtime switches
# ============================================================================


def is_gateway_enabled() -> bool:
    """Whether the gateway and MCP proxy are enabled."""
    config = load_config()
    return _coerce_bool(config.get("enable_gateway", True), True)


def is_unsafe_enabled() -> bool:
    """Whether unsafe tools are enabled."""
    config = load_config()
    return _coerce_bool(config.get("enable_unsafe", False), False)


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
